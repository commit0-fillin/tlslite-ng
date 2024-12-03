"""Handling of Diffie-Hellman parameter files."""
from .utils.asn1parser import ASN1Parser
from .utils.pem import dePem
from .utils.cryptomath import bytesToNumber

def parseBinary(data):
    """
    Parse DH parameters from ASN.1 DER encoded binary string.

    :param bytes data: DH parameters
    :rtype: tuple of int
    """
    parser = ASN1Parser(data)
    if parser.getChildCount() != 2:
        raise ValueError("DH parameters must contain exactly two integers")
    
    prime = bytesToNumber(parser.getChild(0).value)
    generator = bytesToNumber(parser.getChild(1).value)
    return generator, prime

def parse(data):
    """
    Parses DH parameters from a binary string.

    The string can either by PEM or DER encoded

    :param bytes data: DH parameters
    :rtype: tuple of int
    :returns: generator and prime
    """
    try:
        der = dePem(data, "DH PARAMETERS")
    except ValueError:
        der = data
    
    return parseBinary(der)
