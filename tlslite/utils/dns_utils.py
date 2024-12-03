"""Utilities for handling DNS hostnames"""
import re

def is_valid_hostname(hostname):
    """
    Check if the parameter is a valid hostname.

    :type hostname: str or bytearray
    :param hostname: string to check
    :rtype: boolean
    """
    if isinstance(hostname, bytearray):
        hostname = hostname.decode('utf-8')
    
    if not isinstance(hostname, str):
        return False
    
    if len(hostname) > 253:
        return False
    
    hostname = hostname.rstrip(".")
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))
