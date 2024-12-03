"""Implementation of the TLS Record Layer protocol"""
import socket
import errno
import copy
try:
    from itertools import izip
except ImportError:
    izip = zip
try:
    xrange
except NameError:
    xrange = range
from .utils import tlshashlib as hashlib
from .constants import ContentType, CipherSuite
from .messages import RecordHeader3, RecordHeader2, Message
from .utils.cipherfactory import createAESCCM, createAESCCM_8, createAESGCM, createAES, createRC4, createTripleDES, createCHACHA20
from .utils.codec import Parser, Writer
from .utils.compat import compatHMAC
from .utils.cryptomath import getRandomBytes, MD5, HKDF_expand_label
from .utils.constanttime import ct_compare_digest, ct_check_cbc_mac_and_pad
from .errors import TLSRecordOverflow, TLSIllegalParameterException, TLSAbruptCloseError, TLSDecryptionFailed, TLSBadRecordMAC, TLSUnexpectedMessage
from .mathtls import createMAC_SSL, createHMAC, calc_key

class RecordSocket(object):
    """
    Socket wrapper for reading and writing TLS Records.

    :ivar sock: wrapped socket
    :ivar ~.version: version for the records to be encoded on the wire
    :ivar tls13record: flag to indicate that TLS 1.3 specific record limits
        should be used for received records
    :ivar int recv_record_limit: negotiated maximum size of record plaintext
        size
    """

    def __init__(self, sock):
        """
        Assign socket to wrapper

        :type sock: socket.socket
        """
        self.sock = sock
        self.version = (0, 0)
        self.tls13record = False
        self.recv_record_limit = 2 ** 14

    def _sockSendAll(self, data):
        """
        Send all data through socket

        :type data: bytearray
        :param data: data to send
        :raises socket.error: when write to socket failed
        """
        while data:
            try:
                sent = self.sock.send(data)
                data = data[sent:]
            except socket.error as e:
                if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 0
                else:
                    raise

    def send(self, msg, padding=0):
        """
        Send the message through socket.

        :type msg: bytearray
        :param msg: TLS message to send
        :type padding: int
        :param padding: amount of padding to specify for SSLv2
        :raises socket.error: when write to socket failed
        """
        if self.version == (2, 0):
            # SSLv2 encoding
            header = RecordHeader2()
            header.create(len(msg), padding)
            data = header.write() + msg
        else:
            # SSLv3 and TLS encoding
            header = RecordHeader3()
            header.create(self.version, msg.contentType, len(msg))
            data = header.write() + msg.write()

        for result in self._sockSendAll(data):
            yield result

    def _sockRecvAll(self, length):
        """
        Read exactly the amount of bytes specified in L{length} from raw socket.

        :rtype: generator
        :returns: generator that will return 0 or 1 in case the socket is non
            blocking and would block and bytearray in case the read finished
        :raises TLSAbruptCloseError: when the socket closed
        """
        buf = bytearray(0)
        while len(buf) < length:
            try:
                chunk = self.sock.recv(length - len(buf))
                if not chunk:
                    raise TLSAbruptCloseError()
                buf += chunk
            except socket.error as e:
                if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 1
                else:
                    raise

        yield buf

    def _recvHeader(self):
        """Read a single record header from socket"""
        if self.version == (2, 0):
            # SSLv2
            header = RecordHeader2()
            for result in self._sockRecvAll(2):
                if result in (0, 1):
                    yield result
                else:
                    parser = Parser(result)
                    header.parse(parser)
        else:
            # SSLv3 and TLS
            header = RecordHeader3()
            for result in self._sockRecvAll(5):
                if result in (0, 1):
                    yield result
                else:
                    parser = Parser(result)
                    header.parse(parser)

        yield header

    def recv(self):
        """
        Read a single record from socket, handle SSLv2 and SSLv3 record layer

        :rtype: generator
        :returns: generator that returns 0 or 1 in case the read would be
            blocking or a tuple containing record header (object) and record
            data (bytearray) read from socket
        :raises socket.error: In case of network error
        :raises TLSAbruptCloseError: When the socket was closed on the other
            side in middle of record receiving
        :raises TLSRecordOverflow: When the received record was longer than
            allowed by TLS
        :raises TLSIllegalParameterException: When the record header was
            malformed
        """
        for header in self._recvHeader():
            if header in (0, 1):
                yield header
            break

        if isinstance(header, RecordHeader2):
            # SSLv2
            if header.length > self.recv_record_limit:
                raise TLSRecordOverflow()

            for result in self._sockRecvAll(header.length):
                if result in (0, 1):
                    yield result
                else:
                    yield (header, result)
        elif isinstance(header, RecordHeader3):
            # SSLv3 and TLS
            if header.length > self.recv_record_limit:
                raise TLSRecordOverflow()

            for result in self._sockRecvAll(header.length):
                if result in (0, 1):
                    yield result
                else:
                    yield (header, result)
        else:
            raise TLSIllegalParameterException("Received invalid record header")

class ConnectionState(object):
    """Preserve the connection state for reading and writing data to records"""

    def __init__(self):
        """Create an instance with empty encryption and MACing contexts"""
        self.macContext = None
        self.encContext = None
        self.fixedNonce = None
        self.seqnum = 0
        self.encryptThenMAC = False

    def getSeqNumBytes(self):
        """Return encoded sequence number and increment it."""
        pass

    def __copy__(self):
        """Return a copy of the object."""
        ret = ConnectionState()
        ret.macContext = copy.copy(self.macContext)
        ret.encContext = copy.copy(self.encContext)
        ret.fixedNonce = self.fixedNonce
        ret.seqnum = self.seqnum
        ret.encryptThenMAC = self.encryptThenMAC
        return ret

class RecordLayer(object):
    """
    Implementation of TLS record layer protocol

    :ivar ~.version: the TLS version to use (tuple encoded as on the wire)
    :ivar sock: underlying socket
    :ivar client: whether the connection should use encryption
    :ivar handshake_finished: used in SSL2, True if handshake protocol is over
    :ivar tls13record: if True, the record layer will use the TLS 1.3 version
        and content type hiding
    :ivar bool early_data_ok: if True, it's ok to ignore undecryptable records
        up to the size of max_early_data (sum of payloads)
    :ivar int max_early_data: maximum number of bytes that will be processed
        before aborting the connection on data that can not be validated,
        works only if early_data_ok is set to True
    :ivar callable padding_cb: callback used for calculating the size of
        padding to add in TLSv1.3 records
    :ivar int send_record_limit: hint provided to padding callback to not
        generate records larger than the receiving size expects
    :ivar int recv_record_limit: negotiated size of records we are willing to
        accept, TLSRecordOverflow will be raised when records with larger
        plaintext size are received (in TLS 1.3 padding is included in this
        size but encrypted content type is not)
    """

    def __init__(self, sock):
        self.sock = sock
        self._recordSocket = RecordSocket(sock)
        self._version = (0, 0)
        self._tls13record = False
        self.client = True
        self._writeState = ConnectionState()
        self._readState = ConnectionState()
        self._pendingWriteState = ConnectionState()
        self._pendingReadState = ConnectionState()
        self.fixedIVBlock = None
        self.handshake_finished = False
        self.padding_cb = None
        self._early_data_ok = False
        self.max_early_data = 0
        self._early_data_processed = 0
        self.send_record_limit = 2 ** 14

    @property
    def recv_record_limit(self):
        """Maximum record size that is permitted for receiving."""
        pass

    @property
    def early_data_ok(self):
        """
        Set or get the state of early data acceptability.

        If processing of the early_data records is to suceed, even if the
        encryption is not correct, set this property to True. It will be
        automatically reset to False as soon as a decryptable record is
        processed.

        Use max_early_data to set the limit of the total size of records
        that will be processed like this.
        """
        pass

    @property
    def encryptThenMAC(self):
        """
        Set or get the setting of Encrypt Then MAC mechanism.

        set the encrypt-then-MAC mechanism for record
        integrity for next parameter change (after CCS),
        gets current state
        """
        pass

    def _get_pending_state_etm(self):
        """
        Return the state of encrypt then MAC for the connection after
        CCS will be exchanged
        """
        pass

    @property
    def blockSize(self):
        """Return the size of block used by current symmetric cipher (R/O)"""
        pass

    @property
    def tls13record(self):
        """Return the value of the tls13record state."""
        pass

    @tls13record.setter
    def tls13record(self, val):
        """Change the record layer to TLS1.3-like operation, if applicable."""
        pass

    def _is_tls13_plus(self):
        """Returns True if we're doing real TLS 1.3."""
        pass

    def _handle_tls13_record(self):
        """Make sure that the version and tls13record setting is consistent."""
        pass

    @property
    def version(self):
        """Return the TLS version used by record layer"""
        pass

    @version.setter
    def version(self, val):
        """Set the TLS version used by record layer"""
        pass

    def getCipherName(self):
        """
        Return the name of the bulk cipher used by this connection

        :rtype: str
        :returns: The name of the cipher, like 'aes128', 'rc4', etc.
        """
        pass

    def getCipherImplementation(self):
        """
        Return the name of the implementation used for the connection

        'python' for tlslite internal implementation, 'openssl' for M2crypto
        and 'pycrypto' for pycrypto
        :rtype: str
        :returns: Name of cipher implementation used, None if not initialised
        """
        pass

    def shutdown(self):
        """Clear read and write states"""
        pass

    def isCBCMode(self):
        """Returns true if cipher uses CBC mode"""
        pass

    def addPadding(self, data):
        """Add padding to data so that it is multiple of block size"""
        pass

    def calculateMAC(self, mac, seqnumBytes, contentType, data):
        """Calculate the SSL/TLS version of a MAC"""
        pass

    def _macThenEncrypt(self, data, contentType):
        """MAC, pad then encrypt data"""
        pass

    def _encryptThenMAC(self, buf, contentType):
        """Pad, encrypt and then MAC the data"""
        pass

    def _getNonce(self, state, seqnum):
        """Calculate a nonce for a given enc/dec context"""
        pass

    def _encryptThenSeal(self, buf, contentType):
        """Encrypt with AEAD cipher"""
        pass

    def _ssl2Encrypt(self, data):
        """Encrypt in SSL2 mode"""
        pass

    def sendRecord(self, msg):
        """
        Encrypt, MAC and send arbitrary message as-is through socket.

        Note that if the message was not fragmented to below 2**14 bytes
        it will be rejected by the other connection side.

        :param msg: TLS message to send
        :type msg: ApplicationData, HandshakeMessage, etc.
        """
        pass

    def _decryptStreamThenMAC(self, recordType, data):
        """Decrypt a stream cipher and check MAC"""
        pass

    def _decryptThenMAC(self, recordType, data):
        """Decrypt data, check padding and MAC"""
        pass

    def _macThenDecrypt(self, recordType, buf):
        """
        Check MAC of data, then decrypt and remove padding

        :raises TLSBadRecordMAC: when the mac value is invalid
        :raises TLSDecryptionFailed: when the data to decrypt has invalid size
        """
        pass

    def _decryptAndUnseal(self, header, buf):
        """Decrypt AEAD encrypted data"""
        pass

    def _decryptSSL2(self, data, padding):
        """Decrypt SSL2 encrypted data"""
        pass

    @staticmethod
    def _tls13_de_pad(data):
        """
        Remove the padding and extract content type from TLSInnerPlaintext.

        :param bytearray data: decrypted plaintext TLS 1.3 record payload
            (the serialised TLSInnerPlaintext data structure)

        :rtype: tuple
        """
        pass

    def recvRecord(self):
        """
        Read, decrypt and check integrity of a single record

        :rtype: tuple
        :returns: message header and decrypted message payload
        :raises TLSDecryptionFailed: when decryption of data failed
        :raises TLSBadRecordMAC: when record has bad MAC or padding
        :raises socket.error: when reading from socket was unsuccessful
        :raises TLSRecordOverflow: when the received record was longer than
            allowed by negotiated version of TLS
        """
        pass

    def changeWriteState(self):
        """
        Change the cipher state to the pending one for write operations.

        This should be done only once after a call to
        :py:meth:`calcPendingStates` was
        performed and directly after sending a :py:class:`ChangeCipherSpec`
        message.
        """
        pass

    def changeReadState(self):
        """
        Change the cipher state to the pending one for read operations.

        This should be done only once after a call to
        :py:meth:`calcPendingStates` was
        performed and directly after receiving a :py:class:`ChangeCipherSpec`
        message.
        """
        pass

    @staticmethod
    def _getCipherSettings(cipherSuite):
        """Get the settings for cipher suite used"""
        pass

    @staticmethod
    def _getMacSettings(cipherSuite):
        """Get settings for HMAC used"""
        pass

    @staticmethod
    def _getHMACMethod(version):
        """Get the HMAC method"""
        pass

    def calcSSL2PendingStates(self, cipherSuite, masterSecret, clientRandom, serverRandom, implementations):
        """
        Create the keys for encryption and decryption in SSLv2

        While we could reuse calcPendingStates(), we need to provide the
        key-arg data for the server that needs to be passed up to handshake
        protocol.
        """
        pass

    def calcPendingStates(self, cipherSuite, masterSecret, clientRandom, serverRandom, implementations):
        """Create pending states for encryption and decryption."""
        pass

    def calcTLS1_3PendingState(self, cipherSuite, cl_traffic_secret, sr_traffic_secret, implementations):
        """
        Create pending state for encryption in TLS 1.3.

        :param int cipherSuite: cipher suite that will be used for encrypting
            and decrypting data
        :param bytearray cl_traffic_secret: Client Traffic Secret, either
            handshake secret or application data secret
        :param bytearray sr_traffic_secret: Server Traffic Secret, either
            handshake secret or application data secret
        :param list implementations: list of names of implementations that
            are permitted for the connection
        """
        pass
