"""hashlib that handles FIPS mode."""
from hashlib import *
import hashlib

def _fipsFunction(func, *args, **kwargs):
    """Make hash function support FIPS mode."""
    try:
        return func(*args, **kwargs)
    except ValueError as e:
        if "disabled for FIPS" in str(e):
            return hashlib.new(func().name, *args, **kwargs)
        raise

def md5(*args, **kwargs):
    """MD5 constructor that works in FIPS mode."""
    return _fipsFunction(hashlib.md5, *args, **kwargs)

def new(*args, **kwargs):
    """General constructor that works in FIPS mode."""
    return _fipsFunction(hashlib.new, *args, **kwargs)
