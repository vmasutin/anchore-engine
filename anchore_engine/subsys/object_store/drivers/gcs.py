import urllib.parse
import os
from google.cloud import storage

from anchore_engine import utils
from anchore_engine.subsys import logger
from .interface import ObjectStorageDriver
from anchore_engine.subsys.object_store.exc import DriverConfigurationError, ObjectKeyNotFoundError, BadCredentialsError, BucketNotFoundError

class GCSObjectStorageDriver(ObjectStorageDriver):
    """
    Archive driver using GCS api as backing store.

    Buckets presented as part of object lookup in this API are mapped to object key prefixes in the backing GCS store so that a single bucket (or set of buckets)
    can be used since namespaces are limited.

    """
    __config_name__ = 'gcs'
    __driver_version__ = '1'
    __uri_scheme__ = 'gs'

    _key_format = '{prefix}{userid}/{bucket}/{key}'

    def __init__(self, config):
        super(GCSObjectStorageDriver, self).__init__(config)

        self.gcs = None

        if 'service_account_json' in self.config:
            if not os.access(self.config.get('service_account_json'), os.R_OK):
                raise DriverConfigurationError('Cant read GCS credentials file')
        else:
            raise DriverConfigurationError('Missing  "service_account_json" configuration value')


        self.bucket_name = self.config.get('bucket')
        self.create_bucket = self.config.get('create_bucket', False)
        if not self.bucket_name:
            raise ValueError('Cannot configure GCS driver with out a provided bucket to use')

        client = storage.Client.from_service_account_json(self.config.get('service_account_json'))
        self.gcs = client.get_bucket(self.bucket_name)

        self.prefix = self.config.get('prefix', '')

    def _build_key(self, userId, usrBucket, key):
        return self._key_format.format(prefix=self.prefix, userid=userId, bucket=usrBucket,  key=key)

    def get(self, userId, bucket, key):
        uri = self.uri_for(userId, bucket, key)
        return self.get_by_uri(uri)

    def _parse_uri(self, uri):
        parsed = urllib.parse.urlparse(uri, scheme=self.__uri_scheme__)
        bucket = parsed.hostname
        key = parsed.path[1:]
        return bucket, key

    def get_by_uri(self, uri):
        bucket, key = self._parse_uri(uri)
        try:
            resp = self.gcs.get_blob(key)
            content = resp.download_as_string()
            ret = utils.ensure_bytes(content)
            return ret

        except Exception as e:
            raise e

    def put(self, userId, bucket, key, data):
        gen_key = self._build_key(userId, bucket, key)
        try:
            blob = self.gcs.blob(gen_key)
            blob.upload_from_string(data,content_type='binary/octet_stream')
            return self.uri_for(userId, bucket, key)
        except Exception as e:
            raise e

    def delete(self, userId, bucket, key):
        uri = self.uri_for(userId, bucket, key)
        return self.delete_by_uri(uri)

    def delete_by_uri(self, uri):
        bucket, key = self._parse_uri(uri)
        try:
            blob = self.gcs.blob(key)
            blob.delete()
            return True
        except Exception as e:
            raise e

    def uri_for(self, userId, bucket, key):
        return '{}://{}/{}'.format(self.__uri_scheme__, self.bucket_name, self._build_key(userId, bucket, key))
