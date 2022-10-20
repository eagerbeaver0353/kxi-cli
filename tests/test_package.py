from click.testing import CliRunner, tempfile

from kxicli import main


def test_package_list():
    """Test that package api is available'"""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as t:
        result = runner.invoke(main.cli, ["package", f"--pkg-lib={t}", '--artifact-store={t}', "list"])
    assert result.exit_code == 0
    assert result.output.rstrip("\n")[-2:]== "{}"
