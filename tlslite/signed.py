"""Base class that represents any signed object"""
from .utils.cryptomath import numBytes
RSA_SIGNATURE_HASHES = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1']
ALL_RSA_SIGNATURE_HASHES = RSA_SIGNATURE_HASHES + ['md5']
RSA_SCHEMES = ['pss', 'pkcs1']

class SignatureSettings(object):

    def __init__(self, min_key_size=None, max_key_size=None, rsa_sig_hashes=None, rsa_schemes=None):
        """Create default variables for key-related settings."""
        self.min_key_size = min_key_size or 1023
        self.max_key_size = max_key_size or 8193
        self.rsa_sig_hashes = rsa_sig_hashes or list(RSA_SIGNATURE_HASHES)
        self.rsa_schemes = rsa_schemes or list(RSA_SCHEMES)

class SignedObject(object):

    def __init__(self):
        self.tbs_data = None
        self.signature = None
        self.signature_alg = None
    _hash_algs_OIDs = {tuple([42, 134, 72, 134, 247, 13, 1, 1, 4]): 'md5', tuple([42, 134, 72, 134, 247, 13, 1, 1, 5]): 'sha1', tuple([42, 134, 72, 134, 247, 13, 1, 1, 14]): 'sha224', tuple([42, 134, 72, 134, 247, 13, 1, 1, 12]): 'sha384', tuple([42, 134, 72, 134, 247, 13, 1, 1, 11]): 'sha256', tuple([42, 134, 72, 134, 247, 13, 1, 1, 13]): 'sha512'}

    def verify_signature(self, publicKey, settings=None):
        """Verify signature in a response"""
        if settings is None:
            settings = SignatureSettings()

        if self.signature_alg not in self._hash_algs_OIDs.values():
            raise ValueError("Unsupported signature algorithm")

        hash_algorithm = self.signature_alg

        if hash_algorithm not in settings.rsa_sig_hashes:
            raise ValueError("Signature uses unacceptable hash algorithm")

        if publicKey.key_size < settings.min_key_size:
            raise ValueError("Public key too small")
        
        if publicKey.key_size > settings.max_key_size:
            raise ValueError("Public key too large")

        hash_object = tlshashlib.new(hash_algorithm)
        hash_object.update(self.tbs_data)
        digest = hash_object.digest()

        try:
            signature_valid = publicKey.verify(self.signature, digest)
        except:
            signature_valid = False

        return signature_valid
