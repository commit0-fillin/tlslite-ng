"""Class representing an X.509 certificate."""
from ecdsa.keys import VerifyingKey
from .utils.asn1parser import ASN1Parser
from .utils.cryptomath import *
from .utils.keyfactory import _createPublicRSAKey, _create_public_ecdsa_key, _create_public_dsa_key, _create_public_eddsa_key
from .utils.pem import *
from .utils.compat import compatHMAC, b2a_hex
from .constants import AlgorithmOID, RSA_PSS_OID

class X509(object):
    """
    This class represents an X.509 certificate.

    :vartype bytes: bytearray
    :ivar bytes: The DER-encoded ASN.1 certificate

    :vartype publicKey: ~tlslite.utils.rsakey.RSAKey
    :ivar publicKey: The subject public key from the certificate.

    :vartype subject: bytearray
    :ivar subject: The DER-encoded ASN.1 subject distinguished name.

    :vartype certAlg: str
    :ivar certAlg: algorithm of the public key, "rsa" for RSASSA-PKCS#1 v1.5,
        "rsa-pss" for RSASSA-PSS, "ecdsa" for ECDSA
    """

    def __init__(self):
        """Create empty certificate object."""
        self.bytes = bytearray(0)
        self.serial_number = None
        self.subject_public_key = None
        self.publicKey = None
        self.subject = None
        self.certAlg = None
        self.sigalg = None
        self.issuer = None

    def __hash__(self):
        """Calculate hash of object."""
        return hash(bytes(self.bytes))

    def __eq__(self, other):
        """Compare other object for equality."""
        if not hasattr(other, 'bytes'):
            return NotImplemented
        return self.bytes == other.bytes

    def __ne__(self, other):
        """Compare with other object for inequality."""
        if not hasattr(other, 'bytes'):
            return NotImplemented
        return not self == other

    def parse(self, s):
        """
        Parse a PEM-encoded X.509 certificate.

        :type s: str
        :param s: A PEM-encoded X.509 certificate (i.e. a base64-encoded
            certificate wrapped with "-----BEGIN CERTIFICATE-----" and
            "-----END CERTIFICATE-----" tags).
        """
        cert_bytes = dePem(s, "CERTIFICATE")
        self.parseBinary(cert_bytes)

    def parseBinary(self, cert_bytes):
        """
        Parse a DER-encoded X.509 certificate.

        :type bytes: L{str} (in python2) or L{bytearray} of unsigned bytes
        :param bytes: A DER-encoded X.509 certificate.
        """
        self.bytes = bytearray(cert_bytes)
        parser = ASN1Parser(self.bytes)

        # Parse the TBSCertificate
        tbs_certificate = parser.getChild(0)

        # Parse the serial number
        self.serial_number = tbs_certificate.getChild(1).value

        # Parse the subject public key info
        subject_public_key_info = tbs_certificate.getChild(6)
        algorithm = subject_public_key_info.getChild(0).getChild(0).value
        self.subject_public_key = subject_public_key_info.getChild(1).value

        # Parse the subject
        self.subject = tbs_certificate.getChild(5).value

        # Determine the certificate algorithm
        if algorithm == AlgorithmOID.oid[RSA_PSS_OID]:
            self.certAlg = "rsa-pss"
        elif algorithm in AlgorithmOID.oid:
            self.certAlg = SignatureScheme.getKeyType(AlgorithmOID.oid[algorithm])
        else:
            raise SyntaxError("Unknown public key algorithm")

        # Parse the signature algorithm
        signature_algorithm = parser.getChild(1).getChild(0).value
        if signature_algorithm in AlgorithmOID.oid:
            self.sigalg = AlgorithmOID.oid[signature_algorithm]
        else:
            raise SyntaxError("Unknown signature algorithm")

        # Parse the issuer
        self.issuer = tbs_certificate.getChild(3).value

        # Parse the public key based on the algorithm
        if self.certAlg == "rsa" or self.certAlg == "rsa-pss":
            self._rsa_pubkey_parsing(subject_public_key_info)
        elif self.certAlg == "ecdsa":
            self._ecdsa_pubkey_parsing(subject_public_key_info)
        elif self.certAlg == "dsa":
            self._dsa_pubkey_parsing(subject_public_key_info)
        elif self.certAlg in ("ed25519", "ed448"):
            self._eddsa_pubkey_parsing(subject_public_key_info)
        else:
            raise SyntaxError("Unsupported public key algorithm")

    def _eddsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded EdDSA parameters into public key object.

        :param subject_public_key_info: bytes like object with the DER encoded
            public key in it
        """
        public_key = subject_public_key_info.getChild(1).value
        self.publicKey = _create_public_eddsa_key(public_key)

    def _rsa_pubkey_parsing(self, subject_public_key_info):
        """
        Parse the RSA public key from the certificate.

        :param subject_public_key_info: ASN1Parser object with subject
            public key info of X.509 certificate
        """
        key_data = subject_public_key_info.getChild(1).value
        key_parser = ASN1Parser(key_data)
        modulus = key_parser.getChild(0).value
        public_exponent = key_parser.getChild(1).value
        self.publicKey = _createPublicKey((modulus, public_exponent))

    def _ecdsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded ECDSA parameters into public key object

        :param subject_public_key_info: bytes like object with DER encoded
            public key in it
        """
        curve_oid = subject_public_key_info.getChild(0).getChild(1).value
        public_key = subject_public_key_info.getChild(1).value
        curve_name = GroupName.toRepr(AlgorithmOID.oid[curve_oid])
        x, y = self._parse_ec_point(public_key)
        self.publicKey = _create_public_ecdsa_key(x, y, curve_name)

    def _dsa_pubkey_parsing(self, subject_public_key_info):
        """
        Convert the raw DER encoded DSA parameters into public key object

        :param subject_public_key_info: bytes like object with DER encoded
          global parameters and public key in it
        """
        param_data = subject_public_key_info.getChild(0).getChild(1).value
        param_parser = ASN1Parser(param_data)
        p = bytesToNumber(param_parser.getChild(0).value)
        q = bytesToNumber(param_parser.getChild(1).value)
        g = bytesToNumber(param_parser.getChild(2).value)
        y = bytesToNumber(subject_public_key_info.getChild(1).value)
        self.publicKey = _create_public_dsa_key(p, q, g, y)

    def getFingerprint(self):
        """
        Get the hex-encoded fingerprint of this certificate.

        :rtype: str
        :returns: A hex-encoded fingerprint.
        """
        return binascii.hexlify(SHA1(self.bytes)).decode('ascii')

    def writeBytes(self):
        """Serialise object to a DER encoded string."""
        return bytes(self.bytes)

    def _parse_ec_point(self, data):
        """
        Parse EC point from the given data.

        :param data: bytes object containing the EC point
        :return: tuple (x, y) representing the EC point coordinates
        """
        if data[0] != 4:  # uncompressed point
            raise ValueError("Only uncompressed points are supported")
        byte_len = (len(data) - 1) // 2
        x = bytesToNumber(data[1:1+byte_len])
        y = bytesToNumber(data[1+byte_len:])
        return x, y
