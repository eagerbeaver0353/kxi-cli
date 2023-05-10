from pathlib import Path
import kubernetes as k8s

_, active_context = k8s.config.list_kube_config_contexts()
test_namespace = active_context['context']['namespace']
test_cluster = active_context['context']['cluster']

test_host = 'https://test.kx.com'
test_chart_repo_name = 'internal-nexus-dev'
test_chart_repo_url = 'https://nexus.internal-insights.kx.com/repository/kx-helm-charts-dev'
test_image_repo = 'test-repo.internal-insights.kx.com'
test_user = 'user'
test_pass = 'password'
test_cert = str(Path(__file__).parent / 'files' / 'test-cert')
test_key = str(Path(__file__).parent / 'files' / 'test-key')
test_ingress_cert_secret = 'kxi-ingress-cert'

test_docker_config_json = str(Path(__file__).parent / 'files' / 'test-docker-config-json')
test_lic_file = str(Path(__file__).parent / 'files' / 'test-license')

insights_tgz = str(Path(__file__).parent / 'files/helm/insights-1.5.0.tgz')
operator_tgz = str(Path(__file__).parent / 'files/helm/kxi-operator-1.5.0.tgz')
operator_tgz_123 = str(Path(__file__).parent / 'files/helm/kxi-operator-1.2.3.tgz')