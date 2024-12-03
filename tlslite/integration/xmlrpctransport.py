"""TLS Lite + xmlrpclib."""
try:
    import xmlrpclib
    import httplib
except ImportError:
    from xmlrpc import client as xmlrpclib
    from http import client as httplib
from tlslite.integration.httptlsconnection import HTTPTLSConnection
from tlslite.integration.clienthelper import ClientHelper
import tlslite.errors

class XMLRPCTransport(xmlrpclib.Transport, ClientHelper):
    """Handles an HTTPS transaction to an XML-RPC server."""
    transport = xmlrpclib.Transport()
    conn_class_is_http = not hasattr(transport, '_connection')
    del transport

    def __init__(self, use_datetime=0, username=None, password=None, certChain=None, privateKey=None, checker=None, settings=None, ignoreAbruptClose=False):
        """
        Create a new XMLRPCTransport.

        An instance of this class can be passed to
        :py:class:`xmlrpclib.ServerProxy`
        to use TLS with XML-RPC calls::

            from tlslite import XMLRPCTransport
            from xmlrpclib import ServerProxy

            transport = XMLRPCTransport(user="alice", password="abra123")
            server = ServerProxy("https://localhost", transport)

        For client authentication, use one of these argument
        combinations:

         - username, password (SRP)
         - certChain, privateKey (certificate)

        For server authentication, you can either rely on the
        implicit mutual authentication performed by SRP or
        you can do certificate-based server
        authentication with one of these argument combinations:

         - x509Fingerprint

        Certificate-based server authentication is compatible with
        SRP or certificate-based client authentication.

        The constructor does not perform the TLS handshake itself, but
        simply stores these arguments for later.  The handshake is
        performed only when this class needs to connect with the
        server.  Thus you should be prepared to handle TLS-specific
        exceptions when calling methods of :py:class:`xmlrpclib.ServerProxy`.
        See the
        client handshake functions in
        :py:class:`~tlslite.tlsconnection.TLSConnection` for details on which
        exceptions might be raised.

        :type username: str
        :param username: SRP username.  Requires the
            'password' argument.

        :type password: str
        :param password: SRP password for mutual authentication.
            Requires the 'username' argument.

        :type certChain: ~tlslite.x509certchain.X509CertChain
        :param certChain: Certificate chain for client authentication.
            Requires the 'privateKey' argument.  Excludes the SRP arguments.

        :type privateKey: ~tlslite.utils.rsakey.RSAKey
        :param privateKey: Private key for client authentication.
            Requires the 'certChain' argument.  Excludes the SRP arguments.

        :type checker: ~tlslite.checker.Checker
        :param checker: Callable object called after handshaking to
            evaluate the connection and raise an Exception if necessary.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :type ignoreAbruptClose: bool
        :param ignoreAbruptClose: ignore the TLSAbruptCloseError on
            unexpected hangup.
        """
        self._connection = (None, None)
        xmlrpclib.Transport.__init__(self, use_datetime)
        self.ignoreAbruptClose = ignoreAbruptClose
        ClientHelper.__init__(self, username, password, certChain, privateKey, checker, settings)
        self.use_datetime = use_datetime

    def make_connection(self, host):
        """Make a connection to `host`. Reuse keepalive connections."""
        if self.conn_class_is_http:
            # Python 2.7 or earlier, use old-style connection
            chost, self._extra_headers, x509 = self.get_host_info(host)
            return HTTPTLSConnection(
                chost,
                None,
                username=self.username,
                password=self.password,
                certChain=self.certChain,
                privateKey=self.privateKey,
                checker=self.checker,
                settings=self.settings,
                ignoreAbruptClose=self.ignoreAbruptClose
            )
        else:
            # Python 3.x, use new-style connection
            chost, self._extra_headers, x509 = self.get_host_info(host)
            return self._connection_class(
                chost,
                None,
                username=self.username,
                password=self.password,
                certChain=self.certChain,
                privateKey=self.privateKey,
                checker=self.checker,
                settings=self.settings,
                ignoreAbruptClose=self.ignoreAbruptClose
            )
