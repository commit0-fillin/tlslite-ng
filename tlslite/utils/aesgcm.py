from __future__ import division
from tlslite.utils import python_aes
from .constanttime import ct_compare_digest
from .cryptomath import bytesToNumber, numberToByteArray

class AESGCM(object):
    """
    AES-GCM implementation. Note: this implementation does not attempt
    to be side-channel resistant. It's also rather slow.
    """

    def __init__(self, key, implementation, rawAesEncrypt):
        self.isBlockCipher = False
        self.isAEAD = True
        self.nonceLength = 12
        self.tagLength = 16
        self.implementation = implementation
        if len(key) == 16:
            self.name = 'aes128gcm'
        elif len(key) == 32:
            self.name = 'aes256gcm'
        else:
            raise AssertionError()
        self.key = key
        self._rawAesEncrypt = rawAesEncrypt
        self._ctr = python_aes.new(self.key, 6, bytearray(b'\x00' * 16))
        h = bytesToNumber(self._rawAesEncrypt(bytearray(16)))
        self._productTable = [0] * 16
        self._productTable[self._reverseBits(1)] = h
        for i in range(2, 16, 2):
            self._productTable[self._reverseBits(i)] = self._gcmShift(self._productTable[self._reverseBits(i // 2)])
            self._productTable[self._reverseBits(i + 1)] = self._gcmAdd(self._productTable[self._reverseBits(i)], h)

    def _mul(self, y):
        """ Returns y*H, where H is the GCM key. """
        z = 0
        for i in range(128):
            if y & (1 << (127 - i)):
                z ^= self._productTable[i]
        return z

    def seal(self, nonce, plaintext, data):
        """
        Encrypts and authenticates plaintext using nonce and data. Returns the
        ciphertext, consisting of the encrypted plaintext and tag concatenated.
        """
        if len(nonce) != self.nonceLength:
            raise ValueError("Nonce must be 12 bytes long")
        
        # Calculate the initial counter value
        counter = bytesToNumber(nonce + b'\x00\x00\x00\x01')
        
        # Encrypt the plaintext
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            keystream = self._rawAesEncrypt(numberToByteArray(counter, 16))
            ciphertext.extend(bytearray(a ^ b for a, b in zip(block, keystream)))
            counter += 1
        
        # Calculate the authentication tag
        lenA = len(data)
        lenC = len(ciphertext)
        ghash = self._mul(lenA << 3) ^ self._mul(lenC << 3)
        for i in range(0, lenA, 16):
            ghash ^= self._mul(bytesToNumber(data[i:i+16].ljust(16, b'\x00')))
        for i in range(0, lenC, 16):
            ghash ^= self._mul(bytesToNumber(ciphertext[i:i+16].ljust(16, b'\x00')))
        
        tag = numberToByteArray(ghash ^ bytesToNumber(self._rawAesEncrypt(nonce + b'\x00\x00\x00\x01')), 16)
        
        return ciphertext + tag

    def open(self, nonce, ciphertext, data):
        """
        Decrypts and authenticates ciphertext using nonce and data. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.
        """
        if len(nonce) != self.nonceLength:
            raise ValueError("Nonce must be 12 bytes long")
        
        if len(ciphertext) < self.tagLength:
            return None
        
        tag = ciphertext[-self.tagLength:]
        ciphertext = ciphertext[:-self.tagLength]
        
        # Calculate the initial counter value
        counter = bytesToNumber(nonce + b'\x00\x00\x00\x01')
        
        # Decrypt the ciphertext
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            keystream = self._rawAesEncrypt(numberToByteArray(counter, 16))
            plaintext.extend(bytearray(a ^ b for a, b in zip(block, keystream)))
            counter += 1
        
        # Calculate the authentication tag
        lenA = len(data)
        lenC = len(ciphertext)
        ghash = self._mul(lenA << 3) ^ self._mul(lenC << 3)
        for i in range(0, lenA, 16):
            ghash ^= self._mul(bytesToNumber(data[i:i+16].ljust(16, b'\x00')))
        for i in range(0, lenC, 16):
            ghash ^= self._mul(bytesToNumber(ciphertext[i:i+16].ljust(16, b'\x00')))
        
        calculated_tag = numberToByteArray(ghash ^ bytesToNumber(self._rawAesEncrypt(nonce + b'\x00\x00\x00\x01')), 16)
        
        if ct_compare_digest(tag, calculated_tag):
            return plaintext
        else:
            return None
    _gcmReductionTable = [0, 7200, 14400, 9312, 28800, 27808, 18624, 21728, 57600, 64800, 55616, 50528, 37248, 36256, 43456, 46560]
