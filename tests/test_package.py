import tempfile

from click.testing import CliRunner

from kxicli import main


def test_package_list():
    """Test that package api is available'"""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as t:
        result = runner.invoke(main.cli, ["package", f"--pkg-lib={t}", f"--artifact-store={t}", "list"])
    assert result.exit_code == 0
    assert result.output.rstrip("\n")[-2:]== "{}"
