import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def temp_docker_config(docker_config: str):
    temp_dir: str = str(tempfile.mkdtemp())
    try:
        with open(Path(temp_dir).joinpath('config.json'), 'w') as docker_config_json:
            docker_config_json.write(docker_config)
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir)
