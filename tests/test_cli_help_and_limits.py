import argparse

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
