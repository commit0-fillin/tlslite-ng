"""Miscellaneous functions to mask Python version differences."""
import sys
import re
import os
import platform
import math
import binascii
import traceback
import time
import ecdsa
if sys.version_info >= (3, 0):
    if sys.version_info < (3, 4):

        def compatHMAC(x):
            """Convert bytes-like input to format acceptable for HMAC."""
            if isinstance(x, bytearray):
                return bytes(x)
            return x
    else:

        def compatHMAC(x):
            """Convert bytes-like input to format acceptable for HMAC."""
            pass

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        if isinstance(val, str):
            return val.encode('ascii')
        return val

    def compat_b2a(val):
        """Convert an ASCII bytes string to string."""
        if isinstance(val, bytes):
            return val.decode('ascii')
        return val
    int_types = tuple([int])

    def formatExceptionTrace(e):
        """Return exception information formatted as string"""
        return ''.join(traceback.format_exception(type(e), e, e.__traceback__))

    def time_stamp():
        """Returns system time as a float"""
        return time.time()

    def remove_whitespace(text):
        """Removes all whitespace from passed in string"""
        return re.sub(r'\s+', '', text)
    bytes_to_int = int.from_bytes

    def bit_length(val):
        """Return number of bits necessary to represent an integer."""
        return val.bit_length()

    def int_to_bytes(val, length=None, byteorder='big'):
        """Return number converted to bytes"""
        if length is None:
            length = (val.bit_length() + 7) // 8
        return val.to_bytes(length, byteorder)
else:
    if sys.version_info < (2, 7) or sys.version_info < (2, 7, 4) or platform.system() == 'Java':

        def remove_whitespace(text):
            """Removes all whitespace from passed in string"""
            pass

        def bit_length(val):
            """Return number of bits necessary to represent an integer."""
            pass
    else:

        def remove_whitespace(text):
            """Removes all whitespace from passed in string"""
            pass

        def bit_length(val):
            """Return number of bits necessary to represent an integer."""
            pass

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        pass

    def compat_b2a(val):
        """Convert an ASCII bytes string to string."""
        pass
    int_types = (int, long)

    def formatExceptionTrace(e):
        """Return exception information formatted as string"""
        pass

    def time_stamp():
        """Returns system time as a float"""
        pass

    def bytes_to_int(val, byteorder):
        """Convert bytes to an int."""
        return int.from_bytes(val, byteorder)

    def int_to_bytes(val, length=None, byteorder='big'):
        """Return number converted to bytes"""
        pass

def byte_length(val):
    """Return number of bytes necessary to represent an integer."""
    return (val.bit_length() + 7) // 8
try:
    getattr(ecdsa, 'NIST192p')
except AttributeError:
    ecdsaAllCurves = False
else:
    ecdsaAllCurves = True
