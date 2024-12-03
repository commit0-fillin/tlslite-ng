"""Pure Python implementation of ChaCha cipher

Implementation that follows RFC 7539 closely.
"""
from __future__ import division
from .compat import compat26Str
import copy
import struct
try:
    from itertools import izip
except ImportError:
    izip = zip

class ChaCha(object):
    """Pure python implementation of ChaCha cipher"""
    constants = [1634760805, 857760878, 2036477234, 1797285236]

    @staticmethod
    def rotl32(v, c):
        """Rotate left a 32 bit integer v by c bits"""
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """Perform a ChaCha quarter round"""
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = ChaCha.rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = ChaCha.rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = ChaCha.rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = ChaCha.rotl32(x[b] ^ x[c], 7)
    _round_mixup_box = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15), (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]

    @classmethod
    def double_round(cls, x):
        """Perform two rounds of ChaCha cipher"""
        for a, b, c, d in cls._round_mixup_box:
            cls.quarter_round(x, a, b, c, d)

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        """Generate a state of a single block"""
        state = ChaCha.constants + key + [counter] + nonce
        working_state = state[:]
        for _ in range(rounds // 2):
            ChaCha.double_round(working_state)
        return [((working_state[i] + state[i]) & 0xffffffff) for i in range(16)]

    @staticmethod
    def word_to_bytearray(state):
        """Convert state to little endian bytestream"""
        return bytearray(struct.pack('<' + 'I' * 16, *state))

    @staticmethod
    def _bytearray_to_words(data):
        """Convert a bytearray to array of word sized ints"""
        return list(struct.unpack('<' + 'I' * (len(data) // 4), data))

    def __init__(self, key, nonce, counter=0, rounds=20):
        """Set the initial state for the ChaCha cipher"""
        if len(key) != 32:
            raise ValueError('Key must be 256 bit long')
        if len(nonce) != 12:
            raise ValueError('Nonce must be 96 bit long')
        self.key = []
        self.nonce = []
        self.counter = counter
        self.rounds = rounds
        self.key = ChaCha._bytearray_to_words(key)
        self.nonce = ChaCha._bytearray_to_words(nonce)

    def encrypt(self, plaintext):
        """Encrypt the data"""
        encrypted = bytearray()
        for i in range(0, len(plaintext), 64):
            key_stream = self.chacha_block(self.key, self.counter, self.nonce, self.rounds)
            key_stream = self.word_to_bytearray(key_stream)
            chunk = plaintext[i:i+64]
            encrypted.extend(a ^ b for a, b in izip(chunk, key_stream))
            self.counter += 1
        return encrypted

    def decrypt(self, ciphertext):
        """Decrypt the data"""
        return self.encrypt(ciphertext)  # ChaCha is a stream cipher, so encryption and decryption are the same operation
