from pathlib import Path
import yaml
from kxicli import common
from kxicli.resources import helm


class Chart():
    def __init__(self, full_ref: str):
        self.full_ref = full_ref.rstrip('/')
        self.is_remote = not (Path(self.full_ref).is_file() or Path(self.full_ref).is_dir())
        self.repo_name = None

        # if it's an OCI registry, make sure we have the min version installed
        if self.full_ref.startswith('oci://'):
            self.repo_name = "/".join(self.full_ref.split('/')[:-1])
            helm_version_checked = helm.get_helm_version_checked()
            helm_version_checked.ok()
        elif self.full_ref.startswith('http'):
            self.repo_name = "/".join(self.full_ref.split('/')[:-1])
        elif self.is_remote:
            # non-absolute URLs should be in form of repo_name/path_to_chart
            self.repo_name = self.full_ref.split('/')[0]
            helm.repo_exists(self.repo_name)
            helm.repo_update([self.repo_name])

    def __str__(self):
        return self.full_ref

    def get_local_versions(self, top_level_folder='kxi-operator'):
        data = common.extract_files_from_tar( Path(self.full_ref), [f'{top_level_folder}/Chart.yaml'])
        chart_yaml = yaml.safe_load(data[0])
        return [chart_yaml[k] for k in ['appVersion', 'version']]
