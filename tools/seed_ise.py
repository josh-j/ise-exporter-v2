#!/usr/bin/env python
"""Seed a production-like population into a lab ISE via the public ERS API
(ciscoisesdk) so the exporter's collectors can be vetted against realistic data
WITHOUT a live 802.1X fleet, DHCP fingerprinting, or the ISE GUI.

Why this works: the exporter reads endpoint `profileId` (and NAD/session attrs)
from ERS/MnT. ISE cannot tell a *statically*-assigned profile from a
*dynamically*-classified one (`staticProfileAssignment` is just a flag the
exporter doesn't gate on), so ERS static assignment yields the identical data
shape the exporter emits. Profiler *policy* creation has no public API (ERS 405,
OpenAPI absent, ciscoisesdk read-only), so we assign the 900 built-in profiles
directly instead of trying to classify.

Scope note: the exporter emits NO metric from endpoint identity-groups or custom
attributes — only profileId (ERS) and session other_attr_string (MnT). So this
seeds the two dimensions that are actually vetted: the endpoint profile breakdown
(here) and authorization profiles for the session dimension (--authz).

Config via env (same names the exporter uses):
    ISE_HOST      (PAN/ERS; default 10.81.0.10)
    ISE_MNT_HOST  (MnT; defaults to ISE_HOST)
    ISE_USER      (ERS admin, e.g. admin)
    ISE_PASS
    ISE_ERS_PORT  (default 9060)

Usage:
    python tools/seed_ise.py seed [N]     # create N endpoints (default 150), weighted profile mix
    python tools/seed_ise.py verify        # per-profile counts via ERS (the exporter's view)
    python tools/seed_ise.py authz         # create a few authorization profiles (session-dim vetting)
    python tools/seed_ise.py teardown      # delete everything this tool created (MAC prefix + name prefix)
"""
import os
import sys
import random
import urllib3

urllib3.disable_warnings()
from ciscoisesdk import IdentityServicesEngineAPI  # noqa: E402  (must follow disable_warnings)

MAC_PREFIX = "0A:5E:ED"     # locally-administered marker => trivial teardown
MARKER = "vet-seed"         # description marker + authz-profile name prefix

# Realistic enterprise mix (built-in profile name, relative weight).
PROFILE_MIX = [
    ("Windows10-Workstation", 38), ("Windows11-Workstation", 22),
    ("Microsoft-Workstation", 5),  ("Linux-Workstation", 7),
    ("Apple-iPhone", 8),           ("Apple-iPad", 4),
    ("Android", 5),                ("Cisco-IP-Phone", 5),
    ("HP-Device", 2),              ("Canon-Device", 1),
    ("VMWare-Device", 2),          ("Axis-Device", 1),
]

# Authorization profiles to create for session-dimension vetting. Kept minimal
# (name + access_type) — the exporter keys on the profile NAME in the session's
# SelectedAuthorizationProfiles, not on vlan/dACL detail (which need structured
# objects and aren't emitted anyway).
AUTHZ_PROFILES = [
    dict(name=f"{MARKER}-Employee-Full",   access_type="ACCESS_ACCEPT"),
    dict(name=f"{MARKER}-Contractor-Web",  access_type="ACCESS_ACCEPT"),
    dict(name=f"{MARKER}-Quarantine",      access_type="ACCESS_REJECT"),
]


def connect():
    host = os.environ.get("ISE_HOST", "10.81.0.10")
    mnt_host = os.environ.get("ISE_MNT_HOST", host)
    # ERS_PORT is the name the exporter uses; accept the older ISE_ERS_PORT as a fallback.
    port = os.environ.get("ERS_PORT") or os.environ.get("ISE_ERS_PORT", "9060")
    user = os.environ.get("ISE_USER") or sys.exit("set ISE_USER")
    pw = os.environ.get("ISE_PASS") or sys.exit("set ISE_PASS")
    return IdentityServicesEngineAPI(
        username=user, password=pw, uses_api_gateway=False,
        ers_base_url=f"https://{host}:{port}", ui_base_url=f"https://{host}",
        mnt_base_url=f"https://{mnt_host}", px_grid_base_url=f"https://{host}:8910",
        version="3.3_patch_1", verify=False, debug=False, uses_csrf_token=False)


def _profile_ids(api):
    out = []
    for name, w in PROFILE_MIX:
        r = api.profiler_profile.get_profiler_profiles(filter=f"name.EQ.{name}")
        res = r.response.SearchResult.resources
        if res:
            out.append((name, res[0].id, w))
        else:
            print(f"  ! profile not found, skipping: {name}")
    return out


def _rand_mac():
    return "%s:%02X:%02X:%02X" % (MAC_PREFIX, random.randint(0, 255),
                                  random.randint(0, 255), random.randint(0, 255))


def _seeded_endpoints(api):
    macs, page = [], 1
    while True:
        r = api.endpoint.get_endpoints(filter=f"mac.STARTSW.{MAC_PREFIX}", size=100, page=page)
        res = r.response.SearchResult.resources or []
        macs += [(x.id, x.name) for x in res]
        if len(res) < 100:
            return macs
        page += 1


def seed(api, n):
    profs = _profile_ids(api)
    pool = [(nm, pid) for nm, pid, w in profs for _ in range(w)]
    if not pool:
        print("no profiles resolved from PROFILE_MIX — nothing to seed "
              "(check the profile names still exist in ISE)")
        return 1
    made, err = 0, 0
    counts = {}
    for _ in range(n):
        nm, pid = random.choice(pool)
        try:
            api.endpoint.create_endpoint(mac=_rand_mac(), profile_id=pid,
                                         static_profile_assignment=True, description=MARKER)
            made += 1
            counts[nm] = counts.get(nm, 0) + 1
        except Exception as e:
            err += 1
            if err <= 3:
                print("  err:", repr(e)[:120])
    print(f"seeded {made} endpoints ({err} errors)")
    for nm in sorted(counts):
        print(f"  {nm:24s} {counts[nm]}")
    return 0 if made else 1


def verify(api):
    print("endpoints per profile (ERS filter=profileId.EQ — the exporter's view):")
    total = 0
    for nm, pid, w in _profile_ids(api):
        c = api.endpoint.get_endpoints(filter=f"profileId.EQ.{pid}", size=1, page=1).response.SearchResult.total
        total += c
        print(f"  {nm:24s} {c}")
    print(f"\ntotal listed: {total} ; seeded-marker endpoints ({MAC_PREFIX}*): {len(_seeded_endpoints(api))}")
    return 0


def authz(api):
    print("creating authorization profiles (session-dimension vetting):")
    for spec in AUTHZ_PROFILES:
        try:
            api.authorization_profile.create_authorization_profile(**spec)
            print(f"  + {spec['name']} ({spec['access_type']})")
        except Exception as e:
            s = repr(e)
            exists = "exist" in s.lower()
            print(f"  {'~ exists' if exists else 'err'}: {spec['name']} {'' if exists else s[:80]}")
    print("note: to land these in MnT sessions, wire them into the Default policy set's authz "
          "rules and drive `adws auth <ws> <user>` — then ise_session_authz_rule_endpoints populates.")
    return 0


def teardown(api):
    eps = _seeded_endpoints(api)
    print(f"deleting {len(eps)} seeded endpoints...")
    d = 0
    for eid, name in eps:
        try:
            api.endpoint.delete_endpoint_by_id(id=eid)
            d += 1
        except Exception as e:
            print("  del err", name, repr(e)[:80])
    print(f"deleted {d} endpoints")
    # authz profiles
    for spec in AUTHZ_PROFILES:
        try:
            r = api.authorization_profile.get_authorization_profile_by_name(name=spec["name"])
            pid = r.response.AuthorizationProfile.id
            api.authorization_profile.delete_authorization_profile_by_id(id=pid)
            print(f"  deleted authz profile {spec['name']}")
        except Exception:
            pass
    return 0 if d == len(eps) else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    api = connect()
    if cmd == "seed":
        try:
            n = int(sys.argv[2]) if len(sys.argv) > 2 else 150
        except ValueError:
            sys.exit(f"seed count must be an integer, got {sys.argv[2]!r}")
        return seed(api, n)
    if cmd == "authz":
        return authz(api)
    if cmd == "teardown":
        return teardown(api)
    return verify(api)


if __name__ == "__main__":
    sys.exit(main())
