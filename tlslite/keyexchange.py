"""Handling of cryptographic operations for key exchange"""
import ecdsa
from .mathtls import goodGroupParameters, makeK, makeU, makeX, paramStrength, RFC7919_GROUPS, calc_key
from .errors import TLSInsufficientSecurity, TLSUnknownPSKIdentity, TLSIllegalParameterException, TLSDecryptionFailed, TLSInternalError, TLSDecodeError
from .messages import ServerKeyExchange, ClientKeyExchange, CertificateVerify
from .constants import SignatureAlgorithm, HashAlgorithm, CipherSuite, ExtensionType, GroupName, ECCurveType, SignatureScheme
from .utils.ecc import getCurveByName, getPointByteSize
from .utils.rsakey import RSAKey
from .utils.cryptomath import bytesToNumber, getRandomBytes, powMod, numBits, numberToByteArray, divceil, numBytes, secureHash
from .utils.lists import getFirstMatching
from .utils import tlshashlib as hashlib
from .utils.x25519 import x25519, x448, X25519_G, X448_G, X25519_ORDER_SIZE, X448_ORDER_SIZE
from .utils.compat import int_types
from .utils.codec import DecodeError

class KeyExchange(object):
    """
    Common API for calculating Premaster secret

    NOT stable, will get moved from this file
    """

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey=None):
        """Initialize KeyExchange. privateKey is the signing private key"""
        self.cipherSuite = cipherSuite
        self.clientHello = clientHello
        self.serverHello = serverHello
        self.privateKey = privateKey

    def makeServerKeyExchange(self, sigHash=None):
        """
        Create a ServerKeyExchange object

        Returns a ServerKeyExchange object for the server's initial leg in the
        handshake. If the key exchange method does not send ServerKeyExchange
        (e.g. RSA), it returns None.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def makeClientKeyExchange(self):
        """
        Create a ClientKeyExchange object

        Returns a ClientKeyExchange for the second flight from client in the
        handshake.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def processClientKeyExchange(self, clientKeyExchange):
        """
        Process ClientKeyExchange and return premaster secret

        Processes the client's ClientKeyExchange message and returns the
        premaster secret. Raises TLSLocalAlert on error.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Process the server KEX and return premaster secret"""
        raise NotImplementedError("Subclasses must implement this method")

    def _tls12_sign_dsa_SKE(self, serverKeyExchange, sigHash=None):
        """Sign a TLSv1.2 SKE message."""
        raise NotImplementedError("Subclasses must implement this method")

    def _tls12_sign_eddsa_ske(self, server_key_exchange, sig_hash):
        """Sign a TLSv1.2 SKE message."""
        raise NotImplementedError("Subclasses must implement this method")

    def _tls12_signSKE(self, serverKeyExchange, sigHash=None):
        """Sign a TLSv1.2 SKE message."""
        raise NotImplementedError("Subclasses must implement this method")

    def signServerKeyExchange(self, serverKeyExchange, sigHash=None):
        """
        Sign a server key exchange using default or specified algorithm

        :type sigHash: str
        :param sigHash: name of the signature hash to be used for signing
        """
        raise NotImplementedError("Subclasses must implement this method")

    @staticmethod
    def _tls12_verify_eddsa_ske(server_key_exchange, public_key, client_random, server_random, valid_sig_algs):
        """Verify SeverKeyExchange messages with EdDSA signatures."""
        raise NotImplementedError("This method must be implemented")

    @staticmethod
    def _tls12_verify_SKE(serverKeyExchange, publicKey, clientRandom, serverRandom, validSigAlgs):
        """Verify TLSv1.2 version of SKE."""
        raise NotImplementedError("This method must be implemented")

    @staticmethod
    def verifyServerKeyExchange(serverKeyExchange, publicKey, clientRandom, serverRandom, validSigAlgs):
        """Verify signature on the Server Key Exchange message

        the only acceptable signature algorithms are specified by validSigAlgs
        """
        raise NotImplementedError("This method must be implemented")

    @staticmethod
    def calcVerifyBytes(version, handshakeHashes, signatureAlg, premasterSecret, clientRandom, serverRandom, prf_name=None, peer_tag=b'client', key_type='rsa'):
        """Calculate signed bytes for Certificate Verify"""
        raise NotImplementedError("This method must be implemented")

    @staticmethod
    def makeCertificateVerify(version, handshakeHashes, validSigAlgs, privateKey, certificateRequest, premasterSecret, clientRandom, serverRandom):
        """Create a Certificate Verify message

        :param version: protocol version in use
        :param handshakeHashes: the running hash of all handshake messages
        :param validSigAlgs: acceptable signature algorithms for client side,
            applicable only to TLSv1.2 (or later)
        :param certificateRequest: the server provided Certificate Request
            message
        :param premasterSecret: the premaster secret, needed only for SSLv3
        :param clientRandom: client provided random value, needed only for
            SSLv3
        :param serverRandom: server provided random value, needed only for
            SSLv3
        """
        raise NotImplementedError("This method must be implemented")

class AuthenticatedKeyExchange(KeyExchange):
    """
    Common methods for key exchanges that authenticate Server Key Exchange

    Methods for signing Server Key Exchange message
    """

    def makeServerKeyExchange(self, sigHash=None):
        """Prepare server side of key exchange with selected parameters"""
        pass

class RSAKeyExchange(KeyExchange):
    """
    Handling of RSA key exchange

    NOT stable API, do NOT use
    """

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey):
        super(RSAKeyExchange, self).__init__(cipherSuite, clientHello, serverHello, privateKey)
        self.encPremasterSecret = None

    def makeServerKeyExchange(self, sigHash=None):
        """Don't create a server key exchange for RSA key exchange"""
        pass

    def processClientKeyExchange(self, clientKeyExchange):
        """Decrypt client key exchange, return premaster secret"""
        pass

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Generate premaster secret for server"""
        pass

    def makeClientKeyExchange(self):
        """Return a client key exchange with clients key share"""
        pass

class ADHKeyExchange(KeyExchange):
    """
    Handling of anonymous Diffie-Hellman Key exchange

    FFDHE without signing serverKeyExchange useful for anonymous DH
    """

    def __init__(self, cipherSuite, clientHello, serverHello, dhParams=None, dhGroups=None):
        super(ADHKeyExchange, self).__init__(cipherSuite, clientHello, serverHello)
        self.dh_Xs = None
        self.dh_Yc = None
        if dhParams:
            self.dh_g, self.dh_p = dhParams
        else:
            self.dh_g, self.dh_p = goodGroupParameters[2]
        self.dhGroups = dhGroups

    def makeServerKeyExchange(self):
        """
        Prepare server side of anonymous key exchange with selected parameters
        """
        pass

    def processClientKeyExchange(self, clientKeyExchange):
        """Use client provided parameters to establish premaster secret"""
        pass

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Process the server key exchange, return premaster secret."""
        pass

    def makeClientKeyExchange(self):
        """Create client key share for the key exchange"""
        pass

class DHE_RSAKeyExchange(AuthenticatedKeyExchange, ADHKeyExchange):
    """
    Handling of authenticated ephemeral Diffe-Hellman Key exchange.
    """

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey, dhParams=None, dhGroups=None):
        """
        Create helper object for Diffie-Hellamn key exchange.

        :param dhParams: Diffie-Hellman parameters that will be used by
            server. First element of the tuple is the generator, the second
            is the prime. If not specified it will use a secure set (currently
            a 2048-bit safe prime).
        :type dhParams: 2-element tuple of int
        """
        super(DHE_RSAKeyExchange, self).__init__(cipherSuite, clientHello, serverHello, dhParams, dhGroups)
        self.privateKey = privateKey

class AECDHKeyExchange(KeyExchange):
    """
    Handling of anonymous Eliptic curve Diffie-Hellman Key exchange

    ECDHE without signing serverKeyExchange useful for anonymous ECDH
    """

    def __init__(self, cipherSuite, clientHello, serverHello, acceptedCurves, defaultCurve=GroupName.secp256r1):
        super(AECDHKeyExchange, self).__init__(cipherSuite, clientHello, serverHello)
        self.ecdhXs = None
        self.acceptedCurves = acceptedCurves
        self.group_id = None
        self.ecdhYc = None
        self.defaultCurve = defaultCurve

    def makeServerKeyExchange(self, sigHash=None):
        """Create AECDHE version of Server Key Exchange"""
        pass

    def processClientKeyExchange(self, clientKeyExchange):
        """Calculate premaster secret from previously generated SKE and CKE"""
        pass

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Process the server key exchange, return premaster secret"""
        pass

    def makeClientKeyExchange(self):
        """Make client key exchange for ECDHE"""
        pass

class ECDHE_RSAKeyExchange(AuthenticatedKeyExchange, AECDHKeyExchange):
    """Helper class for conducting ECDHE key exchange"""

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey, acceptedCurves, defaultCurve=GroupName.secp256r1):
        super(ECDHE_RSAKeyExchange, self).__init__(cipherSuite, clientHello, serverHello, acceptedCurves, defaultCurve)
        self.privateKey = privateKey

class SRPKeyExchange(KeyExchange):
    """Helper class for conducting SRP key exchange"""

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey, verifierDB, srpUsername=None, password=None, settings=None):
        """Link Key Exchange options with verifierDB for SRP"""
        super(SRPKeyExchange, self).__init__(cipherSuite, clientHello, serverHello, privateKey)
        self.N = None
        self.v = None
        self.b = None
        self.B = None
        self.verifierDB = verifierDB
        self.A = None
        self.srpUsername = srpUsername
        self.password = password
        self.settings = settings
        if srpUsername is not None and (not isinstance(srpUsername, bytearray)):
            raise TypeError('srpUsername must be a bytearray object')
        if password is not None and (not isinstance(password, bytearray)):
            raise TypeError('password must be a bytearray object')

    def makeServerKeyExchange(self, sigHash=None):
        """Create SRP version of Server Key Exchange"""
        pass

    def processClientKeyExchange(self, clientKeyExchange):
        """Calculate premaster secret from Client Key Exchange and sent SKE"""
        pass

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Calculate premaster secret from ServerKeyExchange"""
        pass

    def makeClientKeyExchange(self):
        """Create ClientKeyExchange"""
        pass

class RawDHKeyExchange(object):
    """
    Abstract class for performing Diffe-Hellman key exchange.

    Provides a shared API for X25519, ECDHE and FFDHE key exchange.
    """

    def __init__(self, group, version):
        """
        Set the parameters of the key exchange

        Sets group on which the KEX will take part and protocol version used.
        """
        self.group = group
        self.version = version

    def get_random_private_key(self):
        """
        Generate a random value suitable for use as the private value of KEX.
        """
        pass

    def calc_public_value(self, private):
        """Calculate the public value from the provided private value."""
        pass

    def calc_shared_key(self, private, peer_share):
        """Calcualte the shared key given our private and remote share value"""
        pass

class FFDHKeyExchange(RawDHKeyExchange):
    """Implemenation of the Finite Field Diffie-Hellman key exchange."""

    def __init__(self, group, version, generator=None, prime=None):
        super(FFDHKeyExchange, self).__init__(group, version)
        if prime and group:
            raise ValueError("Can't set the RFC7919 group and custom params at the same time")
        if group:
            self.generator, self.prime = RFC7919_GROUPS[group - 256]
        else:
            self.prime = prime
            self.generator = generator
        if not 1 < self.generator < self.prime:
            raise TLSIllegalParameterException('Invalid DH generator')

    def get_random_private_key(self):
        """
        Return a random private value for the prime used.

        :rtype: int
        """
        pass

    def calc_public_value(self, private):
        """
        Calculate the public value for given private value.

        :rtype: int
        """
        pass

    def _normalise_peer_share(self, peer_share):
        """Convert the peer_share to number if necessary."""
        pass

    def calc_shared_key(self, private, peer_share):
        """Calculate the shared key."""
        pass

class ECDHKeyExchange(RawDHKeyExchange):
    """Implementation of the Elliptic Curve Diffie-Hellman key exchange."""
    _x_groups = set((GroupName.x25519, GroupName.x448))

    @staticmethod
    def _non_zero_check(value):
        """
        Verify using constant time operation that the bytearray is not zero

        :raises TLSIllegalParameterException: if the value is all zero
        """
        pass

    def __init__(self, group, version):
        super(ECDHKeyExchange, self).__init__(group, version)

    def get_random_private_key(self):
        """Return random private key value for the selected curve."""
        pass

    def _get_fun_gen_size(self):
        """Return the function and generator for X25519/X448 KEX."""
        pass

    def calc_public_value(self, private):
        """Calculate public value for given private key."""
        pass

    def calc_shared_key(self, private, peer_share):
        """Calculate the shared key,"""
        pass
