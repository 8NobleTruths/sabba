"""Security command templates ship in the package and install into a Claude Code config dir."""
from pathlib import Path

import sabba.templates


def test_templates_ship_with_the_package():
    src = Path(sabba.templates.__file__).parent / "commands"
    names = {f.stem for f in src.glob("*.md")}
    assert {"pentest", "audit", "vet-skill", "prove-fix"} <= names


def test_templates_install_copies_commands(tmp_path):
    from typer.testing import CliRunner

    from sabba.cli import app
    r = CliRunner().invoke(app, ["templates", "install", "--dir", str(tmp_path)])
    assert r.exit_code == 0
    installed = {f.stem for f in (tmp_path / "commands").glob("*.md")}
    assert {"pentest", "audit", "vet-skill", "prove-fix"} <= installed


def test_templates_list_runs(tmp_path):
    from typer.testing import CliRunner

    from sabba.cli import app
    r = CliRunner().invoke(app, ["templates", "list"])
    assert r.exit_code == 0
    assert "pentest" in r.stdout
