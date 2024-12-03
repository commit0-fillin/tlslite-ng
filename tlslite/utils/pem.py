from .compat import *
import binascii

def dePem(s, name):
    """Decode a PEM string into a bytearray of its payload.
    
    The input must contain an appropriate PEM prefix and postfix
    based on the input name string, e.g. for name="CERTIFICATE"::

      -----BEGIN CERTIFICATE-----
      MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
      ...
      KoZIhvcNAQEFBQADAwA5kw==
      -----END CERTIFICATE-----

    The first such PEM block in the input will be found, and its
    payload will be base64 decoded and returned.
    """
    start = s.find(f"-----BEGIN {name}-----")
    end = s.find(f"-----END {name}-----")
    if start == -1 or end == -1:
        raise ValueError(f"Unable to find {name} PEM block")
    
    s = s[start + len(f"-----BEGIN {name}-----"):end]
    s = remove_whitespace(s)
    return bytearray(binascii.a2b_base64(compatAscii2Bytes(s)))

def dePemList(s, name):
    """Decode a sequence of PEM blocks into a list of bytearrays.

    The input must contain any number of PEM blocks, each with the appropriate
    PEM prefix and postfix based on the input name string, e.g. for
    name="TACK BREAK SIG".  Arbitrary text can appear between and before and
    after the PEM blocks.  For example::

        Created by TACK.py 0.9.3 Created at 2012-02-01T00:30:10Z
        -----BEGIN TACK BREAK SIG-----
        ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
        YMEBdw69PUP8JB4AdqA3K6Ap0Fgd9SSTOECeAKOUAym8zcYaXUwpk0+WuPYa7Zmm
        SkbOlK4ywqt+amhWbg9txSGUwFO5tWUHT3QrnRlE/e3PeNFXLx5Bckg=
        -----END TACK BREAK SIG-----
        Created by TACK.py 0.9.3 Created at 2012-02-01T00:30:11Z
        -----BEGIN TACK BREAK SIG-----
        ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
        YMEBdw69PUP8JB4AdqA3K6BVCWfcjN36lx6JwxmZQncS6sww7DecFO/qjSePCxwM
        +kdDqX/9/183nmjx6bf0ewhPXkA0nVXsDYZaydN8rJU1GaMlnjcIYxY=
        -----END TACK BREAK SIG-----
    
    All such PEM blocks will be found, decoded, and return in an ordered list
    of bytearrays, which may have zero elements if not PEM blocks are found.
    """
    bList = []
    start = 0
    while True:
        start = s.find(f"-----BEGIN {name}-----", start)
        if start == -1:
            break
        end = s.find(f"-----END {name}-----", start)
        if end == -1:
            break
        bList.append(dePem(s[start:end+len(f"-----END {name}-----")], name))
        start = end + len(f"-----END {name}-----")
    return bList

def pem(b, name):
    """Encode a payload bytearray into a PEM string.
    
    The input will be base64 encoded, then wrapped in a PEM prefix/postfix
    based on the name string, e.g. for name="CERTIFICATE"::
    
        -----BEGIN CERTIFICATE-----
        MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
        ...
        KoZIhvcNAQEFBQADAwA5kw==
        -----END CERTIFICATE-----
    """
    s = binascii.b2a_base64(b).decode('ascii')
    s = ''.join(s.split())  # Remove any whitespace
    s = '\n'.join(s[i:i+64] for i in range(0, len(s), 64))  # Add newlines every 64 characters
    s = f"-----BEGIN {name}-----\n{s}\n-----END {name}-----\n"
    return s
