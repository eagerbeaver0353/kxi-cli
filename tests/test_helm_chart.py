from pathlib import Path
from kxicli.resources import helm_chart

# Helpers

def assert_repo_name(full_ref, repo):
    chart = helm_chart.Chart(full_ref)
    assert chart.repo_name == repo

    # confirm resilient to trailing slash
    chart = helm_chart.Chart(f"{full_ref}/")
    assert chart.repo_name == repo

def mock_helm_calls(mocker):
    mocker.patch("kxicli.resources.helm.repo_exists")
    mocker.patch("kxicli.resources.helm.repo_update")
    mocker.patch("kxicli.resources.helm.get_helm_version_checked")

# Tests

def test_folder_or_file_sets_is_remote(mocker):
    # Ensure that file based Chart sets is_local
    # so we know we don't need to do repo updates etc
    file = str(Path(__file__).parent / 'files/helm/kxi-operator-1.2.3.tgz')
    file_chart = helm_chart.Chart(file)
    assert not file_chart.is_remote

    # We don't need to confirm that the folder is an actual chart
    # since we pass this through to 'helm' which will do the validation that its the correct structure
    folder = str(Path(__file__).parent / 'files/helm')
    folder_chart = helm_chart.Chart(folder)
    assert not folder_chart.is_remote

    mock_helm_calls(mocker)
    remote_chart = helm_chart.Chart('kx-insights/insights')
    assert remote_chart.is_remote

    remote_chart = helm_chart.Chart('http://repo.io/insights')
    assert remote_chart.is_remote

    remote_chart = helm_chart.Chart('oci://repo.io/insights')
    assert remote_chart.is_remote


def test_repo_name_gets_parsed_correctly(mocker):
    mock_helm_calls(mocker)

    # OCI
    repo = "oci://repo.io"
    full_ref = f"{repo}/insights"
    assert_repo_name(full_ref, repo)

    # HTTP
    repo = "http://repo.io"
    full_ref = f"{repo}/insights"
    assert_repo_name(full_ref, repo)

    # Chart Ref
    repo = "kx-insights"
    full_ref = f"{repo}/insights"
    assert_repo_name(full_ref, repo)


def test_oci_triggers_helm_version_check(mocker):
    mock_version_check = mocker.patch("kxicli.resources.helm.get_helm_version_checked")
    helm_chart.Chart('oci://repo.io/insights')
    assert mock_version_check.call_count == 1


def test_chart_ref_triggers_repo_update(mocker):
    mock_repo_update = mocker.patch("kxicli.resources.helm.repo_update")
    mock_repo_exists = mocker.patch("kxicli.resources.helm.repo_exists")

    helm_chart.Chart('kx-insights/insights')
    assert mock_repo_update.call_count == 1
    assert mock_repo_exists.call_count == 1

