"""xmlrpcserver.py - simple XML RPC server supporting TLS."""
try:
    from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
except ImportError:
    from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from .tlssocketservermixin import TLSSocketServerMixIn

class TLSXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    """XMLRPCRequestHandler using TLS."""

    def setup(self):
        """Setup the connection for TLS."""
        self.connection = self.request
        self.rfile = self.connection.makefile('rb', self.rbufsize)
        self.wfile = self.connection.makefile('wb', self.wbufsize)

    def do_POST(self):
        """Handle the HTTPS POST request."""
        try:
            # Get the request data
            content_len = int(self.headers.get('content-length', 0))
            post_body = self.rfile.read(content_len)

            # Process the request
            response = self.server._marshaled_dispatch(
                post_body, getattr(self, '_dispatch', None), self.path
            )

            # Send response
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.send_header("Content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            self.wfile.flush()
        except Exception as e:
            self.send_error(500, "XML-RPC request failed: %s" % str(e))

class TLSXMLRPCServer(TLSSocketServerMixIn, SimpleXMLRPCServer):
    """Simple XML-RPC server using TLS."""

    def __init__(self, addr, *args, **kwargs):
        if not args and (not 'requestHandler' in kwargs):
            kwargs['requestHandler'] = TLSXMLRPCRequestHandler
        SimpleXMLRPCServer.__init__(self, addr, *args, **kwargs)

class MultiPathTLSXMLRPCServer(TLSXMLRPCServer):
    """Multipath XML-RPC Server using TLS."""

    def __init__(self, addr, *args, **kwargs):
        TLSXMLRPCServer.__init__(addr, *args, **kwargs)
        self.dispatchers = {}
        self.allow_none = allow_none
        self.encoding = encoding
