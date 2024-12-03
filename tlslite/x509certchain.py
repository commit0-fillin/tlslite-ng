"""Class representing an X.509 certificate chain."""
from .utils import cryptomath
from .utils.tackwrapper import *
from .utils.pem import *
from .x509 import X509

class X509CertChain(object):
    """This class represents a chain of X.509 certificates.

    :vartype x509List: list
    :ivar x509List: A list of :py:class:`tlslite.x509.X509` instances,
        starting with the end-entity certificate and with every
        subsequent certificate certifying the previous.
    """

    def __init__(self, x509List=None):
        """Create a new X509CertChain.

        :type x509List: list
        :param x509List: A list of :py:class:`tlslite.x509.X509` instances,
            starting with the end-entity certificate and with every
            subsequent certificate certifying the previous.
        """
        if x509List:
            self.x509List = x509List
        else:
            self.x509List = []

    def __hash__(self):
        """Return hash of the object."""
        return hash(tuple(self.x509List))

    def __eq__(self, other):
        """Compare objects with each-other."""
        if not hasattr(other, 'x509List'):
            return NotImplemented
        return self.x509List == other.x509List

    def __ne__(self, other):
        """Compare object for inequality."""
        if not hasattr(other, 'x509List'):
            return NotImplemented
        return self.x509List != other.x509List

    def parsePemList(self, s):
        """Parse a string containing a sequence of PEM certs.

        Raise a SyntaxError if input is malformed.
        """
        try:
            self.x509List = [X509().parse(cert) for cert in dePemList(s, "CERTIFICATE")]
        except ValueError as e:
            raise SyntaxError(str(e))

    def getNumCerts(self):
        """Get the number of certificates in this chain.

        :rtype: int
        """
        return len(self.x509List)

    def getEndEntityPublicKey(self):
        """Get the public key from the end-entity certificate.

        :rtype: ~tlslite.utils.rsakey.RSAKey`
        """
        if not self.x509List:
            return None
        return self.x509List[0].publicKey

    def getFingerprint(self):
        """Get the hex-encoded fingerprint of the end-entity certificate.

        :rtype: str
        :returns: A hex-encoded fingerprint.
        """
        if not self.x509List:
            return None
        return self.x509List[0].getFingerprint()

    def getTackExt(self):
        """Get the TACK and/or Break Sigs from a TACK Cert in the chain."""
        for cert in self.x509List:
            if cert.certAlg == "tack":
                return cert.tackExt
        return None
