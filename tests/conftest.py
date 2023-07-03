from unittest.mock import PropertyMock
import pyk8s
import pytest
from pytest_mock import MockerFixture


@pytest.fixture
def k8s(mocker: MockerFixture):
    """Kubernetes client mock."""
    mock = mocker.patch("pyk8s.K8sClient")
    mocker.patch("pyk8s.client.K8sClient", mock)
    client = mock.return_value
    setattr(pyk8s, "cl", client)
    
    # Map Kind to plural so the same mocks can be used for Model.methods and Api.methods.
    # eg.: model.create_ will call the same mock method as client.apiname.create.
    kind_name_map = {
            "Secret": "secrets",
            "Assembly": "assemblies",
            "CustomResourceDefinition": "customresourcedefinitions"
    }
    def _get_api(name = None, api_version = None, kind = None, **filter_dict):
        """Add back the default behaviour to the mock for getting kind/version.
        
        Translate Models api object to use the same client.apiname mock by mapping kind to name.
        """
        name = str(kind_name_map.get(str(kind), name))
        api = getattr(client, name)
        type(api).kind = PropertyMock(side_effect=ValueError)
        type(api).group_version = PropertyMock(side_effect=ValueError)
        return api
    
    client.get_api = _get_api
    client.in_cluster = False
    client.config.namespace = "test-namespace"
    client.config.context = "test-context"
    yield client
    delattr(pyk8s, "cl")
