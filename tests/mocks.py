
import kubernetes as k8s
import requests
import json

def list_cluster_custom_object_k8s_api(mock_instance, response={'items': []}):
    mock = mock_instance.patch.object(k8s.client.CustomObjectsApi, 'list_cluster_custom_object')
    mock.side_effect = lambda *args, **kwargs: response
    return mock

def http_response(url, **kwargs):
    """
    Generic HTTP response
    """
    response = requests.Response()
    response.status_code = kwargs.get('status_code', 200)
    response._content = kwargs.get('content', "{}")

    if 200 <= response.status_code < 300:
        return response
    else:
        raise requests.exceptions.HTTPError(response=response)
