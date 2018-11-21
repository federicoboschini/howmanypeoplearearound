from io import BytesIO
from tempfile import TemporaryFile
import gzip
import shutil

def gzip_file(filename, in_memory=True):
    with open(filename, 'rb') as fp:
        if in_memory:
            compressed_fp = BytesIO()
        else:
            compressed_fp = TemporaryFile()
        with gzip.GzipFile(fileobj=compressed_fp, mode='wb') as gz:
            shutil.copyfileobj(fp, gz)
        compressed_fp.seek(0)
        return compressed_fp