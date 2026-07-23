"""Unit coverage for the shared incremental id-tail SQL builder.

Focused on the label projection shape (``_label_projection`` / ``tail_query``)
rather than the tailing state machine, which the per-domain counter tests
(``test_dataconnect_accounting_counters.py`` etc.) already exercise end to end.
"""
from ise_exporter.collectors import dataconnect_tail


def _projection(sql, name):
    """Pull out the ``NVL(...) AS <name>`` fragment for one grouped label."""
    lowered = sql.lower()
    marker = f" as {name.lower()}"
    end = lowered.index(marker)
    # Walk back to the start of the NVL(...) that feeds this alias.
    start = lowered.rindex("nvl(", 0, end)
    return sql[start:end]


def test_bare_label_column_is_to_char_wrapped_ora_01722_regression():
    """RADIUS_ERRORS_VIEW.MESSAGE_CODE is an Oracle NUMBER column. Without the
    TO_CHAR wrap, NVL(message_code, 'unknown') forces Oracle to reconcile the two
    NVL branches by implicitly running TO_NUMBER('unknown') the moment the column
    is genuinely NULL, raising ORA-01722 in production (see collect_error_counters).
    Every bare label column must be projected through TO_CHAR before the NVL
    fallback, not just message_code specifically.
    """
    sql = dataconnect_tail.tail_query(
        "radius_errors_view",
        (("message_code", "message_code", "'unknown'"),
         ("psn", "ise_node", "'unknown'")),
        schema=None)
    lowered = sql.lower()
    assert "nvl(to_char(message_code), 'unknown') as message_code" in lowered
    assert "nvl(to_char(ise_node), 'unknown') as psn" in lowered


def test_bare_label_column_is_to_char_wrapped_with_discovered_schema():
    # Same wrap when the live schema positively confirms the column is present
    # (not just the permissive schema=None path).
    schema = {"RADIUS_ERRORS_VIEW": {
        "ID": {}, "TIMESTAMP": {}, "MESSAGE_CODE": {}, "ISE_NODE": {}}}
    sql = dataconnect_tail.tail_query(
        "radius_errors_view",
        (("message_code", "message_code", "'unknown'"),
         ("psn", "ise_node", "'unknown'")),
        schema=schema)
    lowered = sql.lower()
    assert "nvl(to_char(message_code), 'unknown') as message_code" in lowered
    assert "nvl(to_char(ise_node), 'unknown') as psn" in lowered


def test_explicit_expr_override_is_left_untouched():
    # The auth FAILED -> passed/failed CASE is already Oracle-type-safe and
    # responsible for its own safety; the engine must not also TO_CHAR it.
    case_expr = ("CASE WHEN failed = 1 THEN 'failed'"
                 " WHEN failed = 0 THEN 'passed' ELSE 'unknown' END")
    sql = dataconnect_tail.tail_query(
        "radius_authentications",
        (("result", "failed", "'unknown'", case_expr),
         ("psn", "ise_node", "'unknown'")),
        schema=None)
    lowered = sql.lower()
    assert _projection(sql, "result").lower() == f"nvl({case_expr.lower()}, 'unknown')"
    assert "to_char(failed)" not in lowered
    # The plain psn column alongside it still gets the bare-column wrap.
    assert "nvl(to_char(ise_node), 'unknown') as psn" in lowered


def test_fallback_literal_path_stays_a_plain_literal_when_column_is_absent():
    # Column missing from the discovered schema: base is the caller's safe SQL
    # literal, not a column reference, so it must not be TO_CHAR-wrapped either.
    schema = {"SOME_VIEW": {"ID": {}, "TIMESTAMP": {}}}
    sql = dataconnect_tail.tail_query(
        "some_view",
        (("message_code", "message_code", "'unknown'"),),
        schema=schema)
    lowered = sql.lower()
    assert "nvl('unknown', 'unknown') as message_code" in lowered
    assert "to_char" not in lowered


def test_expr_override_falls_back_to_to_char_wrap_when_column_is_absent():
    # expr is only used when the column is actually present; when the schema
    # shows the column missing, the projection falls back to the (TO_CHAR-wrapped)
    # bare-column path same as any other entry -- but since the column itself is
    # absent, schema_expression substitutes the fallback literal instead.
    schema = {"RADIUS_AUTHENTICATIONS": {"ID": {}, "TIMESTAMP": {}, "ISE_NODE": {}}}
    case_expr = ("CASE WHEN failed = 1 THEN 'failed'"
                 " WHEN failed = 0 THEN 'passed' ELSE 'unknown' END")
    sql = dataconnect_tail.tail_query(
        "radius_authentications",
        (("result", "failed", "'unknown'", case_expr),),
        schema=schema)
    lowered = sql.lower()
    assert "nvl('unknown', 'unknown') as result" in lowered
    assert case_expr.lower() not in lowered
