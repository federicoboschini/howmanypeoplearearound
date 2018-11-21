import boto3
from compressor import gzip_file

s3 = boto3.resource('s3')

def upload_file(filename, bucket_name, compress=True, compress_in_memory=False):
    bucket = s3.Bucket(bucket_name)
    if compress:
        with gzip_file(filename, in_memory=compress_in_memory) as zipped_file:
            bucket.upload_fileobj(zipped_file, filename, {'ContentType': 'text/plain', 'ContentEncoding': 'gzip'})
    else:
        s3.meta.client.upload_file(filename, bucket_name, filename)
