"""cryptomath module

This module has basic math/crypto code."""
from __future__ import print_function
import os
import math
import base64
import binascii
from .compat import compat26Str, compatHMAC, compatLong, bytes_to_int, int_to_bytes, bit_length, byte_length
from .codec import Writer
from . import tlshashlib as hashlib
from . import tlshmac as hmac
try:
    from M2Crypto import m2
    m2cryptoLoaded = True
    M2CRYPTO_AES_CTR = False
    if hasattr(m2, 'aes_192_ctr'):
        M2CRYPTO_AES_CTR = True
    try:
        with open('/proc/sys/crypto/fips_enabled', 'r') as fipsFile:
            if '1' in fipsFile.read():
                m2cryptoLoaded = False
    except (IOError, OSError):
        m2cryptoLoaded = True
    if not hasattr(m2, 'aes_192_cbc'):
        m2cryptoLoaded = False
except ImportError:
    m2cryptoLoaded = False
try:
    import gmpy
    gmpy.mpz
    gmpyLoaded = True
except ImportError:
    gmpyLoaded = False
try:
    from gmpy2 import powmod
    GMPY2_LOADED = True
except ImportError:
    GMPY2_LOADED = False
if GMPY2_LOADED:
    from gmpy2 import mpz
elif gmpyLoaded:
    from gmpy import mpz
try:
    import Crypto.Cipher.AES
    try:
        Crypto.Cipher.AES.AESCipher(b'2' * (128 // 8))
        pycryptoLoaded = True
    except AttributeError:
        pycryptoLoaded = False
except ImportError:
    pycryptoLoaded = False
import zlib
assert len(zlib.compress(os.urandom(1000))) > 900
prngName = 'os.urandom'

def MD5(b):
    """Return a MD5 digest of data"""
    return tlshashlib.md5(b).digest()

def SHA1(b):
    """Return a SHA1 digest of data"""
    return tlshashlib.sha1(b).digest()

def secureHash(data, algorithm):
    """Return a digest of `data` using `algorithm`"""
    return tlshashlib.new(algorithm, data).digest()

def secureHMAC(k, b, algorithm):
    """Return a HMAC using `b` and `k` using `algorithm`"""
    return hmac.new(k, b, algorithm).digest()

def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    """
    TLS1.3 key derivation function (HKDF-Expand-Label).

    :param bytearray secret: the key from which to derive the keying material
    :param bytearray label: label used to differentiate the keying materials
    :param bytearray hashValue: bytes used to "salt" the produced keying
        material
    :param int length: number of bytes to produce
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF
    :rtype: bytearray
    """
    hkdf = hmac.HMAC(secret, algorithm=algorithm)
    info = bytearray([0, length]) + b'tls13 ' + label + hashValue
    return hkdf.derive(info)[:length]

def derive_secret(secret, label, handshake_hashes, algorithm):
    """
    TLS1.3 key derivation function (Derive-Secret).

    :param bytearray secret: secret key used to derive the keying material
    :param bytearray label: label used to differentiate they keying materials
    :param HandshakeHashes handshake_hashes: hashes of the handshake messages
        or `None` if no handshake transcript is to be used for derivation of
        keying material
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF algorithm - governs how much keying material will
        be generated
    :rtype: bytearray
    """
    if handshake_hashes is None:
        handshake_hash = bytearray(tlshashlib.new(algorithm).digest_size)
    else:
        handshake_hash = handshake_hashes.digest(algorithm)
    
    return HKDF_expand_label(secret, label, handshake_hash,
                             tlshashlib.new(algorithm).digest_size,
                             algorithm)

def bytesToNumber(b, endian='big'):
    """
    Convert a number stored in bytearray to an integer.

    By default assumes big-endian encoding of the number.
    """
    return int.from_bytes(b, byteorder=endian)

def numberToByteArray(n, howManyBytes=None, endian='big'):
    """
    Convert an integer into a bytearray, zero-pad to howManyBytes.

    The returned bytearray may be smaller than howManyBytes, but will
    not be larger.  The returned bytearray will contain a big- or little-endian
    encoding of the input integer (n). Big endian encoding is used by default.
    """
    if howManyBytes is None:
        howManyBytes = (n.bit_length() + 7) // 8
    return n.to_bytes(howManyBytes, byteorder=endian)

def mpiToNumber(mpi):
    """Convert a MPI (OpenSSL bignum string) to an integer."""
    byte_length = (mpi[0] * 256 + mpi[1]) // 8
    return bytesToNumber(mpi[4:4+byte_length])
numBits = bit_length
numBytes = byte_length
if GMPY2_LOADED:

    def invMod(a, b):
        """Return inverse of a mod b, zero if none."""
        try:
            return int(gmpy2.invert(a, b))
        except ZeroDivisionError:
            return 0
else:

    def invMod(a, b):
        """Return inverse of a mod b, zero if none."""
        if a == 0:
            return 0
        x1, x2, y1, y2 = 1, 0, 0, 1
        while b:
            q, r = divmod(a, b)
            x1, x2 = x2, x1 - q * x2
            y1, y2 = y2, y1 - q * y2
            a, b = b, r
        if a != 1:
            return 0
        return x1 % b
if gmpyLoaded or GMPY2_LOADED:
else:
    powMod = pow

def divceil(divident, divisor):
    """Integer division with rounding up"""
    return (divident + divisor - 1) // divisor

def getRandomPrime(bits, display=False):
    """
    Generate a random prime number of a given size.

    the number will be 'bits' bits long (i.e. generated number will be
    larger than `(2^(bits-1) * 3 ) / 2` but smaller than 2^bits.
    """
    import random
    def is_prime(n, k=5):
        if n < 2: return False
        for p in [2,3,5,7,11,13,17,19,23,29]:
            if n % p == 0: return n == p
        s, d = 0, n-1
        while d % 2 == 0:
            s, d = s+1, d//2
        for _ in range(k):
            a = random.randrange(2, n-1)
            x = pow(a, d, n)
            if x != 1 and x != n-1:
                for _ in range(s-1):
                    x = pow(x, 2, n)
                    if x == n-1: break
                else: return False
        return True
    
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits-1)) | 1
        if is_prime(p):
            return p

def getRandomSafePrime(bits, display=False):
    """Generate a random safe prime.

    Will generate a prime `bits` bits long (see getRandomPrime) such that
    the (p-1)/2 will also be prime.
    """
    while True:
        p = getRandomPrime(bits, display)
        if is_prime((p - 1) // 2):
            return p
