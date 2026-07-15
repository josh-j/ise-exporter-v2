import argparse
import json
import types

import pytest

from ise_exporter import cli


def _subcommands(parser):
    return next(
        action.choices
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )


def test_every_cli_command_has_working_help(capsys):
    commands = _subcommands(cli.build_parser())

    for name in commands:
        with pytest.raises(SystemExit) as exited:
            cli.main([name, "--help"])
        assert exited.value.code == 0
        output = capsys.readouterr().out
        assert output.startswith(f"usage: ise-cli {name}")
        assert commands[name].description in output
        assert "options:" in output


def test_every_bulk_command_has_a_reasonable_default_limit():
    commands = _subcommands(cli.build_parser())
    expected = {
        "nodes": 50,
        "endpoints": 100,
        "nads": 100,
        "profiles": 100,
        "tacacs-users": 100,
        "identity-groups": 100,
        "network-device-groups": 100,
        "sessions": 100,
        "auth-status": 20,
        "troubleshoot-auth": 20,
        "psn-summary": 25,
        "patches": 100,
        "repositories": 100,
        "network-policy-sets": 100,
        "device-admin-policy-sets": 100,
        "authorization-profiles": 100,
        "tacacs-command-sets": 100,
        "tacacs-shell-profiles": 100,
        "certificates": 100,
        "radius-auth": 100,
        "endpoint-report": 100,
        "radius-errors": 100,
        "radius-accounting": 100,
        "posture": 100,
        "psn-metrics": 100,
        "tacacs-activity": 100,
    }

    for name, default in expected.items():
        limit = next(
            action for action in commands[name]._actions
            if action.dest == "limit"
        )
        assert limit.default == default, name


def test_bulk_limit_must_be_positive_before_live_collection(capsys):
    class Client:
        cfg = types.SimpleNamespace(cli_max_rows=1000, cli_production_safe=True)

        def __init__(self):
            self.calls = []

        def get_pan_api(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return [{"hostname": "ise01"}]

    client = Client()

    assert cli.main(["nodes", "--limit", "0"], client=client) == 2
    assert client.calls == []
    assert "--limit must be at least 1" in capsys.readouterr().err


def test_openapi_inventory_resolves_only_bounded_self_links(capsys):
    class Client:
        cfg = types.SimpleNamespace(cli_max_rows=1000, cli_production_safe=True)

        def __init__(self):
            self.calls = []

        def get_pan_api(self, path, **kwargs):
            self.calls.append((path, kwargs))
            if path == "/policy/network-access/policy-set":
                return [
                    {
                        "id": "first",
                        "name": "Default",
                        "link": {
                            "href": (
                                "https://advertised.invalid/api/v1/policy/"
                                "network-access/policy-set/first"
                            ),
                            "rel": "self",
                        },
                    },
                    {
                        "id": "second",
                        "name": "Not requested",
                        "link": {
                            "href": (
                                "https://advertised.invalid/api/v1/policy/"
                                "network-access/policy-set/second"
                            ),
                            "rel": "self",
                        },
                    },
                ]
            assert path == "/policy/network-access/policy-set/first"
            return {
                "id": "first",
                "name": "Default",
                "authenticationPolicy": {"defaultRule": {"name": "Default"}},
            }

    client = Client()

    assert cli.main(
        ["network-policy-sets", "--limit", "1", "--output", "json"],
        client=client,
    ) == 0
    result = json.loads(capsys.readouterr().out)

    assert result == [{
        "id": "first",
        "name": "Default",
        "authenticationPolicy": {"defaultRule": {"name": "Default"}},
    }]
    assert [call[0] for call in client.calls] == [
        "/policy/network-access/policy-set",
        "/policy/network-access/policy-set/first",
    ]
