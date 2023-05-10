
import kubernetes as k8s

def list_cluster_custom_object_k8s_api(mock_instance, response={'items': []}):
    mock = mock_instance.patch.object(k8s.client.CustomObjectsApi, 'list_cluster_custom_object')
    mock.side_effect = lambda *args, **kwargs: response
    return mock
