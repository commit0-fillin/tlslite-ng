"""
HMAC module that works in FIPS mode.

Note that this makes this code FIPS non-compliant!
"""
from . import tlshashlib
from .compat import compatHMAC
try:
    from hmac import compare_digest
    __all__ = ['new', 'compare_digest', 'HMAC']
except ImportError:
    __all__ = ['new', 'HMAC']
try:
    from hmac import HMAC, new
    _val = HMAC(b'some key', b'msg', 'md5')
    _val.digest()
    del _val
except Exception:

    class HMAC(object):
        """Hacked version of HMAC that works in FIPS mode even with MD5."""

        def __init__(self, key, msg=None, digestmod=None):
            """
            Initialise the HMAC and hash first portion of data.

            msg: data to hash
            digestmod: name of hash or object that be used as a hash and be cloned
            """
            self.key = key
            if digestmod is None:
                digestmod = 'md5'
            if callable(digestmod):
                digestmod = digestmod()
            if not hasattr(digestmod, 'digest_size'):
                digestmod = tlshashlib.new(digestmod)
            self.block_size = digestmod.block_size
            self.digest_size = digestmod.digest_size
            self.digestmod = digestmod
            if len(key) > self.block_size:
                k_hash = digestmod.copy()
                k_hash.update(compatHMAC(key))
                key = k_hash.digest()
            if len(key) < self.block_size:
                key = key + b'\x00' * (self.block_size - len(key))
            key = bytearray(key)
            ipad = bytearray(b'6' * self.block_size)
            opad = bytearray(b'\\' * self.block_size)
            i_key = bytearray((i ^ j for i, j in zip(key, ipad)))
            self._o_key = bytearray((i ^ j for i, j in zip(key, opad)))
            self._context = digestmod.copy()
            self._context.update(compatHMAC(i_key))
            if msg:
                self._context.update(compatHMAC(msg))

    def new(key, msg=None, digestmod=None):
        """General constructor that works in FIPS mode."""
        return HMAC(key, msg, digestmod)
