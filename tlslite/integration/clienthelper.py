"""
A helper class for using TLS Lite with stdlib clients
(httplib, xmlrpclib, imaplib, poplib).
"""
from tlslite.checker import Checker
from tlslite.utils.dns_utils import is_valid_hostname

class ClientHelper(object):
    """This is a helper class used to integrate TLS Lite with various
    TLS clients (e.g. poplib, smtplib, httplib, etc.)"""

    def __init__(self, username=None, password=None, certChain=None, privateKey=None, checker=None, settings=None, anon=False, host=None):
        """
        For client authentication, use one of these argument
        combinations:

         - username, password (SRP)
         - certChain, privateKey (certificate)

        For server authentication, you can either rely on the
        implicit mutual authentication performed by SRP,
        or you can do certificate-based server
        authentication with one of these argument combinations:

         - x509Fingerprint

        Certificate-based server authentication is compatible with
        SRP or certificate-based client authentication.

        The constructor does not perform the TLS handshake itself, but
        simply stores these arguments for later.  The handshake is
        performed only when this class needs to connect with the
        server.  Then you should be prepared to handle TLS-specific
        exceptions.  See the client handshake functions in
        :py:class:`~tlslite.tlsconnection.TLSConnection` for details on which
        exceptions might be raised.

        :param str username: SRP username.  Requires the
            'password' argument.

        :param str password: SRP password for mutual authentication.
            Requires the 'username' argument.

        :param X509CertChain certChain: Certificate chain for client
            authentication.
            Requires the 'privateKey' argument.  Excludes the SRP arguments.

        :param RSAKey privateKey: Private key for client authentication.
            Requires the 'certChain' argument.  Excludes the SRP arguments.

        :param Checker checker: Callable object called after handshaking to
            evaluate the connection and raise an Exception if necessary.

        :type settings: HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :param bool anon: set to True if the negotiation should advertise only
            anonymous TLS ciphersuites. Mutually exclusive with client
            certificate
            authentication or SRP authentication

        :type host: str or None
        :param host: the hostname that the connection is made to. Can be an
            IP address (in which case the SNI extension won't be sent). Can
            include the port (in which case the port will be stripped and
            ignored).
        """
        self.username = None
        self.password = None
        self.certChain = None
        self.privateKey = None
        self.checker = None
        self.anon = anon
        self.settings = settings
        self.tlsSession = None
        self.serverName = None

        if username and password and (not (certChain or privateKey)):
            self.username = username
            self.password = password
        elif certChain and privateKey and (not (username or password)):
            self.certChain = certChain
            self.privateKey = privateKey
        elif not password and (not username) and (not certChain) and (not privateKey):
            if not anon:
                raise ValueError('Either username/password, certChain/privateKey, or anon must be set')
        else:
            raise ValueError('Bad parameters')

        self.checker = checker

        if host is not None:
            if not self._isIP(host):
                colon = host.find(':')
                if colon > 0:
                    host = host[:colon]
                self.serverName = host
                if host and (not is_valid_hostname(host)):
                    raise ValueError('Invalid hostname: {0}'.format(host))

    @staticmethod
    def _isIP(address):
        """Return True if the address is an IPv4 address"""
        try:
            # Split the address into octets
            octets = address.split('.')
            
            # Check if there are exactly 4 octets
            if len(octets) != 4:
                return False
            
            # Check each octet
            for octet in octets:
                # Check if the octet is a valid integer between 0 and 255
                if not octet.isdigit() or int(octet) < 0 or int(octet) > 255:
                    return False
                
                # Check for leading zeros (not allowed in IPv4)
                if len(octet) > 1 and octet[0] == '0':
                    return False
            
            return True
        except:
            return False
