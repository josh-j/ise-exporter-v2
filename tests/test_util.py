from ise_exporter.util import (normalize_mac, normalize_location,
                               parse_other_attr_string, first_nonempty,
                               normalize_posture, normalize_bool_label)


def test_normalize_mac():
    assert normalize_mac("aa-bb-cc-00-00-01") == "AA:BB:CC:00:00:01"
    assert normalize_mac("") == ""


def test_normalize_location():
    assert normalize_location("All Locations#Germany#Ramstein AB") == "Germany#Ramstein AB"
    assert normalize_location("") == "Unknown"


def test_other_attr_string():
    d = parse_other_attr_string("ISEPolicySetName=Wired Open Mode:!:AuthorizationPolicyMatchedRule=Default")
    assert d["ISEPolicySetName"] == "Wired Open Mode"
    assert d["AuthorizationPolicyMatchedRule"] == "Default"


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
