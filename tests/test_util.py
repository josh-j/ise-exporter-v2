from ise_exporter.util import (normalize_mac, normalize_location,
                               parse_other_attr_string, first_nonempty,
                               normalize_posture, normalize_bool_label,
                               parse_posture_report, normalize_agent_version,
                               parse_step_latencies)


def test_normalize_mac():
    assert normalize_mac("aa-bb-cc-00-00-01") == "AA:BB:CC:00:00:01"
    assert normalize_mac("aabb.cc00.0001") == "AA:BB:CC:00:00:01"
    assert normalize_mac("aabbcc000001") == "AA:BB:CC:00:00:01"
    assert normalize_mac("aa bb cc 00 00 01") == "AA:BB:CC:00:00:01"
    assert normalize_mac("") == ""


def test_normalize_location():
    assert normalize_location("All Locations#Germany#Ramstein AB") == "Germany#Ramstein AB"
    assert normalize_location("") == "Unknown"


def test_other_attr_string():
    d = parse_other_attr_string("ISEPolicySetName=Wired Open Mode:!:AuthorizationPolicyMatchedRule=Default")
    assert d["ISEPolicySetName"] == "Wired Open Mode"
    assert d["AuthorizationPolicyMatchedRule"] == "Default"


def test_parse_step_latencies_pairs_positions_with_execution_codes():
    assert parse_step_latencies(
        "11001, 15049, 24430", "1=0;2=17;3=2") == [
            ("11001", 0.0), ("15049", 0.017), ("24430", 0.002)]


def test_parse_step_latencies_ignores_invalid_values_and_positions():
    assert parse_step_latencies("11001,15049", "0=1;1=-2;2=nan;3=4;x=5") == []


def test_parse_step_latencies_normalizes_and_bounds_step_code_labels():
    assert parse_step_latencies(
        "00001,99999,100000,not-a-code", "1=1;2=2;3=3;4=4") == [
            ("1", 0.001), ("99999", 0.002)]


def test_first_nonempty_oui_fallback():
    a = {"mfcInfoHardwareManufacturer": "", "oui": "Xerox Corp"}
    assert first_nonempty(a, "mfcInfoHardwareManufacturer", "oui") == "Xerox Corp"


def test_normalize_posture_canonicalizes_variants():
    assert normalize_posture("Compliant") == "Compliant"
    assert normalize_posture("non-compliant") == "NonCompliant"
    assert normalize_posture("NON_COMPLIANT") == "NonCompliant"
    assert normalize_posture("Not Applicable") == "NotApplicable"
    assert normalize_posture("") == "NotApplicable"      # no posture ran
    assert normalize_posture(None) == "NotApplicable"
    assert normalize_posture("SomethingNew") == "SomethingNew"   # unknown passthrough


def test_normalize_bool_label():
    assert normalize_bool_label("true") == "true"
    assert normalize_bool_label("Compliant") == "true"
    assert normalize_bool_label("false") == "false"
    assert normalize_bool_label("Unregistered") == "false"
    assert normalize_bool_label("") == "unknown"
    assert normalize_bool_label(None) == "unknown"
    # ISE JSON returns real booleans for fields like staticProfileAssignment;
    # these must not raise (bool has no .strip()) and must map correctly.
    assert normalize_bool_label(True) == "true"
    assert normalize_bool_label(False) == "false"


# a trimmed multi-policy PostureReport in ISE's real format (escaped '\;' separators,
# multiple requirements per policy, condition lists with ':' inside brackets)
_POSTURE_REPORT = (
    "C2CP-WIN-FIREWALL\\;Passed\\;(C2CR-WIN-FIREWALL:Optional:Passed:"
    "Passed_Conditions[C2CC-A:C2CC-B]:Failed_Conditions[]:Skipped_Conditions[]), "
    "C2CP-WIN-AM\\;Failed\\;(C2CR-WIN-AM:Mandatory:Failed:Passed_Conditions[]:"
    "Failed_Conditions[am_x]:Skipped_Conditions[]\\;C2CR-WIN-AM-ATP:Optional:Passed:"
    "Passed_Conditions[atp]:Failed_Conditions[]:Skipped_Conditions[]), "
    "C2CP-WIN-DE-BITLOCKER\\;Passed\\;(C2CR-WIN-DE-BITLOCKER:Optional:Passed:"
    "Passed_Conditions[hd_x]:Failed_Conditions[]:Skipped_Conditions[])"
)


def test_parse_posture_report_policy_level_rollup():
    # one (policy, result) per POLICY — requirement/condition detail is dropped, and a
    # multi-requirement policy (AM, with a nested '\;' requirement) still yields one row
    assert parse_posture_report(_POSTURE_REPORT) == [
        ("C2CP-WIN-FIREWALL", "Passed"),
        ("C2CP-WIN-AM", "Failed"),
        ("C2CP-WIN-DE-BITLOCKER", "Passed"),
    ]


def test_parse_posture_report_empty():
    assert parse_posture_report("") == []
    assert parse_posture_report(None) == []


def test_normalize_agent_version_strips_prefix():
    assert normalize_agent_version("Posture Agent for Windows 5.1.17.3394") == "Windows 5.1.17.3394"
    assert normalize_agent_version("5.1.2.42") == "5.1.2.42"
    assert normalize_agent_version("") == ""
