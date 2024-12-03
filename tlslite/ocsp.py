"""Class for handling primary OCSP responses"""
from .utils.asn1parser import ASN1Parser
from .utils.cryptomath import bytesToNumber, numBytes, secureHash
from .x509 import X509
from .signed import SignedObject
from .errors import TLSIllegalParameterException

class OCSPRespStatus(object):
    """ OCSP response status codes (RFC 2560) """
    successful = 0
    malformedRequest = 1
    internalError = 2
    tryLater = 3
    sigRequired = 5
    unauthorized = 6

class CertStatus(object):
    """ Certificate status in an OCSP response """
    good, revoked, unknown = range(3)

class SingleResponse(object):
    """ This class represents SingleResponse ASN1 type (defined in RFC2560) """

    def __init__(self, value):
        self.value = value
        self.cert_hash_alg = None
        self.cert_issuer_name_hash = None
        self.cert_issuer_key_hash = None
        self.cert_serial_num = None
        self.cert_status = None
        self.this_update = None
        self.next_update = None
        self.parse(value)

    _hash_algs_OIDs = {tuple([42, 134, 72, 134, 247, 13, 2, 5]): 'md5', tuple([43, 14, 3, 2, 26]): 'sha1', tuple([96, 134, 72, 1, 101, 3, 4, 2, 4]): 'sha224', tuple([96, 134, 72, 1, 101, 3, 4, 2, 1]): 'sha256', tuple([96, 134, 72, 1, 101, 3, 4, 2, 2]): 'sha384', tuple([96, 134, 72, 1, 101, 3, 4, 2, 3]): 'sha512'}

    def parse(self, value):
        """
        Parse a SingleResponse ASN.1 structure.

        :type value: ASN1Parser
        :param value: ASN.1 structure of SingleResponse
        """
        cert_id = value.getChild(0)
        
        # Parse certID
        hash_algorithm = cert_id.getChild(0).getChild(0).value
        self.cert_hash_alg = self._hash_algs_OIDs.get(tuple(hash_algorithm), None)
        self.cert_issuer_name_hash = cert_id.getChild(1).value
        self.cert_issuer_key_hash = cert_id.getChild(2).value
        self.cert_serial_num = bytesToNumber(cert_id.getChild(3).value)

        # Parse certStatus
        cert_status = value.getChild(1)
        status_type = cert_status.type.tag_id
        if status_type == 0:
            self.cert_status = CertStatus.good
        elif status_type == 1:
            self.cert_status = CertStatus.revoked
        elif status_type == 2:
            self.cert_status = CertStatus.unknown

        # Parse thisUpdate
        self.this_update = value.getChild(2).value

        # Parse nextUpdate if present
        if value.getChildCount() > 3:
            self.next_update = value.getChild(3).getChild(0).value

class OCSPResponse(SignedObject):
    """ This class represents an OCSP response. """

    def __init__(self, value):
        super(OCSPResponse, self).__init__()
        self.bytes = None
        self.resp_status = None
        self.resp_type = None
        self.version = None
        self.resp_id = None
        self.produced_at = None
        self.responses = []
        self.certs = []
        self.parse(value)

    def parse(self, value):
        """
        Parse a DER-encoded OCSP response.

        :type value: stream of bytes
        :param value: An DER-encoded OCSP response
        """
        self.bytes = bytearray(value)
        parser = ASN1Parser(self.bytes)

        # Parse responseStatus
        resp_status = parser.getChild(0).value[0]
        self.resp_status = resp_status

        if resp_status != OCSPRespStatus.successful:
            return  # No responseBytes if not successful

        # Parse responseBytes
        response_bytes = parser.getChild(1)
        resp_type = response_bytes.getChild(0).value
        self.resp_type = resp_type

        basic_ocsp_response = ASN1Parser(response_bytes.getChild(1).value)
        self._tbsdataparse(basic_ocsp_response.getChild(0))

        # Parse signature
        self.signature = basic_ocsp_response.getChild(1).value

        # Parse signature algorithm
        sig_alg = basic_ocsp_response.getChild(2).getChild(0).value
        self.signature_alg = self._hash_algs_OIDs.get(tuple(sig_alg), None)

        # Parse certs if present
        if basic_ocsp_response.getChildCount() > 3:
            certs = basic_ocsp_response.getChild(3)
            for i in range(certs.getChildCount()):
                cert = X509()
                cert.parseBinary(certs.getChild(i).value)
                self.certs.append(cert)

    def _tbsdataparse(self, value):
        """
        Parse to be signed data,

        :type value: stream of bytes
        :param value: TBS data
        """
        self.tbs_data = value.bytes

        # Parse version
        self.version = value.getChild(0).value[0]

        # Parse responderID
        responder_id = value.getChild(1)
        self.resp_id = responder_id.value

        # Parse producedAt
        self.produced_at = value.getChild(2).value

        # Parse responses
        responses = value.getChild(3)
        for i in range(responses.getChildCount()):
            single_response = SingleResponse(responses.getChild(i))
            self.responses.append(single_response)
