import shutil
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp


@contextmanager
def temp_file(file_name: str, prefix: str = 'kxicli-'):
    dir_name: str = str()
    inited: bool = False
    try:
        dir_name = mkdtemp(prefix=prefix)
        inited = True
        temp_file_name = str(Path(dir_name).joinpath(file_name))
        yield temp_file_name
    finally:
        if inited:
            shutil.rmtree(dir_name)
