from .utils.compat import a2b_hex
'Constants used in various places.'
TLS_1_3_DRAFT = (3, 4)
TLS_1_3_HRR = a2b_hex('CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C')
TLS_1_1_DOWNGRADE_SENTINEL = a2b_hex('444F574E47524400')
TLS_1_2_DOWNGRADE_SENTINEL = a2b_hex('444F574E47524401')
RSA_PSS_OID = bytes(a2b_hex('06092a864886f70d01010a'))

class TLSEnum(object):
    """Base class for different enums of TLS IDs"""

    @classmethod
    def _recursiveVars(cls, klass):
        """Call vars recursively on base classes"""
        result = {}
        for base in klass.__bases__:
            result.update(cls._recursiveVars(base))
        result.update(vars(klass))
        return result

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """
        Convert numeric type to string representation

        name if found, None otherwise
        """
        if blacklist is None:
            blacklist = []
        attrs = cls._recursiveVars(cls)
        for key, val in attrs.items():
            if key[0] != '_' and val == value and key not in blacklist:
                return key
        return None

    @classmethod
    def toStr(cls, value, blacklist=None):
        """Convert numeric type to human-readable string if possible"""
        name = cls.toRepr(value, blacklist)
        if name is None:
            return str(value)
        else:
            return name

class CertificateType(TLSEnum):
    x509 = 0
    openpgp = 1

class ClientCertificateType(TLSEnum):
    rsa_sign = 1
    dss_sign = 2
    rsa_fixed_dh = 3
    dss_fixed_dh = 4
    ecdsa_sign = 64
    rsa_fixed_ecdh = 65
    ecdsa_fixed_ecdh = 66

class SSL2HandshakeType(TLSEnum):
    """SSL2 Handshake Protocol message types."""
    error = 0
    client_hello = 1
    client_master_key = 2
    client_finished = 3
    server_hello = 4
    server_verify = 5
    server_finished = 6
    request_certificate = 7
    client_certificate = 8

class SSL2ErrorDescription(TLSEnum):
    """SSL2 Handshake protocol error message descriptions"""
    no_cipher = 1
    no_certificate = 2
    bad_certificate = 4
    unsupported_certificate_type = 6

class HandshakeType(TLSEnum):
    """Message types in TLS Handshake protocol"""
    hello_request = 0
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    hello_retry_request = 6
    encrypted_extensions = 8
    certificate = 11
    server_key_exchange = 12
    certificate_request = 13
    server_hello_done = 14
    certificate_verify = 15
    client_key_exchange = 16
    finished = 20
    certificate_status = 22
    key_update = 24
    next_protocol = 67
    message_hash = 254

class ContentType(TLSEnum):
    """TLS record layer content types of payloads"""
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
    heartbeat = 24
    all = (20, 21, 22, 23, 24)

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """Convert numeric type to name representation"""
        if blacklist is None:
            blacklist = []
        if isinstance(value, tuple):
            return super(SignatureScheme, cls).toRepr(value, blacklist)
        else:
            return super(SignatureScheme, cls).toRepr((value >> 8, value & 0xFF), blacklist)

class ExtensionType(TLSEnum):
    """TLS Extension Type registry values"""
    server_name = 0
    max_fragment_length = 1
    status_request = 5
    cert_type = 9
    supported_groups = 10
    ec_point_formats = 11
    srp = 12
    signature_algorithms = 13
    heartbeat = 15
    alpn = 16
    client_hello_padding = 21
    encrypt_then_mac = 22
    extended_master_secret = 23
    record_size_limit = 28
    session_ticket = 35
    extended_random = 40
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51
    supports_npn = 13172
    tack = 62208
    renegotiation_info = 65281

class HashAlgorithm(TLSEnum):
    """Hash algorithm IDs used in TLSv1.2"""
    none = 0
    md5 = 1
    sha1 = 2
    sha224 = 3
    sha256 = 4
    sha384 = 5
    sha512 = 6
    intrinsic = 8

class SignatureAlgorithm(TLSEnum):
    """Signing algorithms used in TLSv1.2"""
    anonymous = 0
    rsa = 1
    dsa = 2
    ecdsa = 3
    ed25519 = 7
    ed448 = 8

class SignatureScheme(TLSEnum):
    """
    Signature scheme used for signalling supported signature algorithms.

    This is the replacement for the HashAlgorithm and SignatureAlgorithm
    lists. Introduced with TLSv1.3.
    """
    rsa_pkcs1_sha1 = (2, 1)
    rsa_pkcs1_sha224 = (3, 1)
    rsa_pkcs1_sha256 = (4, 1)
    rsa_pkcs1_sha384 = (5, 1)
    rsa_pkcs1_sha512 = (6, 1)
    ecdsa_sha1 = (2, 3)
    ecdsa_sha224 = (3, 3)
    ecdsa_secp256r1_sha256 = (4, 3)
    ecdsa_secp384r1_sha384 = (5, 3)
    ecdsa_secp521r1_sha512 = (6, 3)
    rsa_pss_rsae_sha256 = (8, 4)
    rsa_pss_rsae_sha384 = (8, 5)
    rsa_pss_rsae_sha512 = (8, 6)
    ed25519 = (8, 7)
    ed448 = (8, 8)
    rsa_pss_pss_sha256 = (8, 9)
    rsa_pss_pss_sha384 = (8, 10)
    rsa_pss_pss_sha512 = (8, 11)
    rsa_pss_sha256 = (8, 4)
    rsa_pss_sha384 = (8, 5)
    rsa_pss_sha512 = (8, 6)
    dsa_sha1 = (2, 2)
    dsa_sha224 = (3, 2)
    dsa_sha256 = (4, 2)
    dsa_sha384 = (5, 2)
    dsa_sha512 = (6, 2)

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """Convert numeric type to name representation"""
        if blacklist is None:
            blacklist = []
        try:
            return super(GroupName, cls).toRepr(value, blacklist)
        except:
            return None

    @staticmethod
    def getKeyType(scheme):
        """
        Return the name of the signature algorithm used in scheme.

        E.g. for "rsa_pkcs1_sha1" it returns "rsa"
        """
        name = SignatureScheme.toStr(scheme)
        if name.startswith(("rsa", "dsa", "ecdsa")):
            return name.split('_')[0]
        elif name.startswith(("ed25519", "ed448")):
            return name
        else:
            raise ValueError("Unknown signature scheme: {}".format(scheme))

    @staticmethod
    def getPadding(scheme):
        """Return the name of padding scheme used in signature scheme."""
        name = SignatureScheme.toStr(scheme)
        if "pkcs1" in name:
            return "pkcs1"
        elif "pss" in name:
            return "pss"
        else:
            return None

    @staticmethod
    def getHash(scheme):
        """Return the name of hash used in signature scheme."""
        name = SignatureScheme.toStr(scheme)
        if "md5" in name:
            return "md5"
        elif "sha1" in name:
            return "sha1"
        elif "sha224" in name:
            return "sha224"
        elif "sha256" in name:
            return "sha256"
        elif "sha384" in name:
            return "sha384"
        elif "sha512" in name:
            return "sha512"
        else:
            return None

class AlgorithmOID(TLSEnum):
    """
    Algorithm OIDs as defined in rfc5758(ecdsa),
    rfc5754(rsa, sha), rfc3447(rss-pss).
    The key is the DER encoded OID in hex and
    the value is the algorithm id.
    """
    oid = {}
    oid[bytes(a2b_hex('06072a8648ce3d0401'))] = SignatureScheme.ecdsa_sha1
    oid[bytes(a2b_hex('06082a8648ce3d040301'))] = SignatureScheme.ecdsa_sha224
    oid[bytes(a2b_hex('06082a8648ce3d040302'))] = SignatureScheme.ecdsa_secp256r1_sha256
    oid[bytes(a2b_hex('06082a8648ce3d040303'))] = SignatureScheme.ecdsa_secp384r1_sha384
    oid[bytes(a2b_hex('06082a8648ce3d040304'))] = SignatureScheme.ecdsa_secp521r1_sha512
    oid[bytes(a2b_hex('06092a864886f70d010104'))] = (HashAlgorithm.md5, SignatureAlgorithm.rsa)
    oid[bytes(a2b_hex('06092a864886f70d010105'))] = SignatureScheme.rsa_pkcs1_sha1
    oid[bytes(a2b_hex('06092a864886f70d01010e'))] = SignatureScheme.rsa_pkcs1_sha224
    oid[bytes(a2b_hex('06092a864886f70d01010b'))] = SignatureScheme.rsa_pkcs1_sha256
    oid[bytes(a2b_hex('06092a864886f70d01010c'))] = SignatureScheme.rsa_pkcs1_sha384
    oid[bytes(a2b_hex('06092a864886f70d01010d'))] = SignatureScheme.rsa_pkcs1_sha512
    oid[bytes(a2b_hex('300b0609608648016503040201'))] = SignatureScheme.rsa_pss_rsae_sha256
    oid[bytes(a2b_hex('300b0609608648016503040202'))] = SignatureScheme.rsa_pss_rsae_sha384
    oid[bytes(a2b_hex('300b0609608648016503040203'))] = SignatureScheme.rsa_pss_rsae_sha512
    oid[bytes(a2b_hex('300d06096086480165030402010500'))] = SignatureScheme.rsa_pss_rsae_sha256
    oid[bytes(a2b_hex('300d06096086480165030402020500'))] = SignatureScheme.rsa_pss_rsae_sha384
    oid[bytes(a2b_hex('300d06096086480165030402030500'))] = SignatureScheme.rsa_pss_rsae_sha512
    oid[bytes(a2b_hex('06072A8648CE380403'))] = SignatureScheme.dsa_sha1
    oid[bytes(a2b_hex('0609608648016503040301'))] = SignatureScheme.dsa_sha224
    oid[bytes(a2b_hex('0609608648016503040302'))] = SignatureScheme.dsa_sha256
    oid[bytes(a2b_hex('0609608648016503040303'))] = SignatureScheme.dsa_sha384
    oid[bytes(a2b_hex('0609608648016503040304'))] = SignatureScheme.dsa_sha512
    oid[bytes(a2b_hex('06032b6570'))] = SignatureScheme.ed25519
    oid[bytes(a2b_hex('06032b6571'))] = SignatureScheme.ed448

class GroupName(TLSEnum):
    """Name of groups supported for (EC)DH key exchange"""
    sect163k1 = 1
    sect163r1 = 2
    sect163r2 = 3
    sect193r1 = 4
    sect193r2 = 5
    sect233k1 = 6
    sect233r1 = 7
    sect239k1 = 8
    sect283k1 = 9
    sect283r1 = 10
    sect409k1 = 11
    sect409r1 = 12
    sect571k1 = 13
    sect571r1 = 14
    secp160k1 = 15
    secp160r1 = 16
    secp160r2 = 17
    secp192k1 = 18
    secp192r1 = 19
    secp224k1 = 20
    secp224r1 = 21
    secp256k1 = 22
    secp256r1 = 23
    secp384r1 = 24
    secp521r1 = 25
    allEC = list(range(1, 26))
    brainpoolP256r1 = 26
    brainpoolP384r1 = 27
    brainpoolP512r1 = 28
    allEC.extend(list(range(26, 29)))
    x25519 = 29
    x448 = 30
    allEC.extend(list(range(29, 31)))
    ffdhe2048 = 256
    ffdhe3072 = 257
    ffdhe4096 = 258
    ffdhe6144 = 259
    ffdhe8192 = 260
    allFF = list(range(256, 261))
    all = allEC + allFF

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """Convert numeric type to name representation"""
        pass
TLS_1_3_FORBIDDEN_GROUPS = frozenset().union(range(1, 23), range(26, 29), (65281, 65282))

class ECPointFormat(TLSEnum):
    """Names and ID's of supported EC point formats."""
    uncompressed = 0
    ansiX962_compressed_prime = 1
    ansiX962_compressed_char2 = 2
    all = [uncompressed, ansiX962_compressed_prime, ansiX962_compressed_char2]

    @classmethod
    def toRepr(cls, value, blacklist=None):
        """Convert numeric type to name representation."""
        pass

class ECCurveType(TLSEnum):
    """Types of ECC curves supported in TLS from RFC4492"""
    explicit_prime = 1
    explicit_char2 = 2
    named_curve = 3

class NameType(TLSEnum):
    """Type of entries in Server Name Indication extension."""
    host_name = 0

class CertificateStatusType(TLSEnum):
    """Type of responses in the status_request and CertificateStatus msgs."""
    ocsp = 1

class HeartbeatMode(TLSEnum):
    """Types of heartbeat modes from RFC 6520"""
    PEER_ALLOWED_TO_SEND = 1
    PEER_NOT_ALLOWED_TO_SEND = 2

class HeartbeatMessageType(TLSEnum):
    """Types of heartbeat messages from RFC 6520"""
    heartbeat_request = 1
    heartbeat_response = 2

class KeyUpdateMessageType(TLSEnum):
    """Types of keyupdate messages from RFC 8446"""
    update_not_requested = 0
    update_requested = 1

class AlertLevel(TLSEnum):
    """Enumeration of TLS Alert protocol levels"""
    warning = 1
    fatal = 2

class AlertDescription(TLSEnum):
    """
    :cvar bad_record_mac: A TLS record failed to decrypt properly.

        If this occurs during a SRP handshake it most likely
        indicates a bad password.  It may also indicate an implementation
        error, or some tampering with the data in transit.

        This alert will be signalled by the server if the SRP password is bad.
        It
        may also be signalled by the server if the SRP username is unknown to
        the
        server, but it doesn't wish to reveal that fact.


    :cvar handshake_failure: A problem occurred while handshaking.

        This typically indicates a lack of common ciphersuites between client
        and
        server, or some other disagreement (about SRP parameters or key sizes,
        for example).

    :cvar protocol_version: The other party's SSL/TLS version was unacceptable.

        This indicates that the client and server couldn't agree on which
        version
        of SSL or TLS to use.

    :cvar user_canceled: The handshake is being cancelled for some reason.
    """
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    decryption_failed = 21
    record_overflow = 22
    decompression_failure = 30
    handshake_failure = 40
    no_certificate = 41
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    export_restriction = 60
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    no_renegotiation = 100
    missing_extension = 109
    unsupported_extension = 110
    certificate_unobtainable = 111
    unrecognized_name = 112
    bad_certificate_status_response = 113
    bad_certificate_hash_value = 114
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120

class PskKeyExchangeMode(TLSEnum):
    """Values used in the PSK Key Exchange Modes extension."""
    psk_ke = 0
    psk_dhe_ke = 1

class CipherSuite:
    """
    Numeric values of ciphersuites and ciphersuite types

    :cvar tripleDESSuites: ciphersuties which use 3DES symmetric cipher in CBC
        mode
    :cvar aes128Suites: ciphersuites which use AES symmetric cipher in CBC mode
        with 128 bit key
    :cvar aes256Suites: ciphersuites which use AES symmetric cipher in CBC mode
        with 256 bit key
    :cvar rc4Suites: ciphersuites which use RC4 symmetric cipher with 128 bit
        key
    :cvar shaSuites: ciphersuites which use SHA-1 HMAC integrity mechanism
        and protocol default Pseudo Random Function
    :cvar sha256Suites: ciphersuites which use SHA-256 HMAC integrity mechanism
        and SHA-256 Pseudo Random Function
    :cvar md5Suites: ciphersuites which use MD-5 HMAC integrity mechanism and
        protocol default Pseudo Random Function
    :cvar srpSuites: ciphersuites which use Secure Remote Password (SRP) key
        exchange protocol
    :cvar srpCertSuites: ciphersuites which use Secure Remote Password (SRP)
        key exchange protocol with RSA server authentication
    :cvar srpAllSuites: all SRP ciphersuites, pure SRP and with RSA based
        server authentication
    :cvar certSuites: ciphersuites which use RSA key exchange with RSA server
        authentication
    :cvar certAllSuites: ciphersuites which use RSA server authentication
    :cvar anonSuites: ciphersuites which use anonymous Finite Field
        Diffie-Hellman key exchange
    :cvar ietfNames: dictionary with string names of the ciphersuites
    """
    ietfNames = {}
    SSL_CK_RC4_128_WITH_MD5 = 65664
    ietfNames[65664] = 'SSL_CK_RC4_128_WITH_MD5'
    SSL_CK_RC4_128_EXPORT40_WITH_MD5 = 131200
    ietfNames[131200] = 'SSL_CK_RC4_128_EXPORT40_WITH_MD5'
    SSL_CK_RC2_128_CBC_WITH_MD5 = 196736
    ietfNames[196736] = 'SSL_CK_RC2_128_CBC_WITH_MD5'
    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = 262272
    ietfNames[262272] = 'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5'
    SSL_CK_IDEA_128_CBC_WITH_MD5 = 327808
    ietfNames[327808] = 'SSL_CK_IDEA_128_CBC_WITH_MD5'
    SSL_CK_DES_64_CBC_WITH_MD5 = 393280
    ietfNames[393280] = 'SSL_CK_DES_64_CBC_WITH_MD5'
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5 = 458944
    ietfNames[458944] = 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5'
    ssl2rc4 = []
    ssl2rc4.append(SSL_CK_RC4_128_WITH_MD5)
    ssl2rc4.append(SSL_CK_RC4_128_EXPORT40_WITH_MD5)
    ssl2rc2 = []
    ssl2rc2.append(SSL_CK_RC2_128_CBC_WITH_MD5)
    ssl2rc2.append(SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)
    ssl2idea = [SSL_CK_IDEA_128_CBC_WITH_MD5]
    ssl2des = [SSL_CK_DES_64_CBC_WITH_MD5]
    ssl2_3des = [SSL_CK_DES_192_EDE3_CBC_WITH_MD5]
    ssl2export = []
    ssl2export.append(SSL_CK_RC4_128_EXPORT40_WITH_MD5)
    ssl2export.append(SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)
    ssl2_128Key = []
    ssl2_128Key.append(SSL_CK_RC4_128_WITH_MD5)
    ssl2_128Key.append(SSL_CK_RC4_128_EXPORT40_WITH_MD5)
    ssl2_128Key.append(SSL_CK_RC2_128_CBC_WITH_MD5)
    ssl2_128Key.append(SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)
    ssl2_128Key.append(SSL_CK_IDEA_128_CBC_WITH_MD5)
    ssl2_64Key = [SSL_CK_DES_64_CBC_WITH_MD5]
    ssl2_192Key = [SSL_CK_DES_192_EDE3_CBC_WITH_MD5]
    TLS_RSA_WITH_NULL_MD5 = 1
    ietfNames[1] = 'TLS_RSA_WITH_NULL_MD5'
    TLS_RSA_WITH_NULL_SHA = 2
    ietfNames[2] = 'TLS_RSA_WITH_NULL_SHA'
    TLS_RSA_WITH_RC4_128_MD5 = 4
    ietfNames[4] = 'TLS_RSA_WITH_RC4_128_MD5'
    TLS_RSA_WITH_RC4_128_SHA = 5
    ietfNames[5] = 'TLS_RSA_WITH_RC4_128_SHA'
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 10
    ietfNames[10] = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 13
    ietfNames[13] = 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA'
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 19
    ietfNames[19] = 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 22
    ietfNames[22] = 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'
    TLS_DH_ANON_WITH_RC4_128_MD5 = 24
    ietfNames[24] = 'TLS_DH_ANON_WITH_RC4_128_MD5'
    TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA = 27
    ietfNames[27] = 'TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA'
    TLS_RSA_WITH_AES_128_CBC_SHA = 47
    ietfNames[47] = 'TLS_RSA_WITH_AES_128_CBC_SHA'
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = 48
    ietfNames[48] = 'TLS_DH_DSS_WITH_AES_128_CBC_SHA'
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 50
    ietfNames[50] = 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA'
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 51
    ietfNames[51] = 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'
    TLS_DH_ANON_WITH_AES_128_CBC_SHA = 52
    ietfNames[52] = 'TLS_DH_ANON_WITH_AES_128_CBC_SHA'
    TLS_RSA_WITH_AES_256_CBC_SHA = 53
    ietfNames[53] = 'TLS_RSA_WITH_AES_256_CBC_SHA'
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = 54
    ietfNames[54] = 'TLS_DH_DSS_WITH_AES_256_CBC_SHA'
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 56
    ietfNames[56] = 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA'
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 57
    ietfNames[57] = 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA'
    TLS_DH_ANON_WITH_AES_256_CBC_SHA = 58
    ietfNames[58] = 'TLS_DH_ANON_WITH_AES_256_CBC_SHA'
    TLS_RSA_WITH_NULL_SHA256 = 59
    ietfNames[59] = 'TLS_RSA_WITH_NULL_SHA256'
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 60
    ietfNames[60] = 'TLS_RSA_WITH_AES_128_CBC_SHA256'
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 61
    ietfNames[61] = 'TLS_RSA_WITH_AES_256_CBC_SHA256'
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 62
    ietfNames[62] = 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256'
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 64
    ietfNames[64] = 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 103
    ietfNames[103] = 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 104
    ietfNames[104] = 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256'
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 106
    ietfNames[106] = 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 107
    ietfNames[107] = 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256'
    TLS_DH_ANON_WITH_AES_128_CBC_SHA256 = 108
    ietfNames[108] = 'TLS_DH_ANON_WITH_AES_128_CBC_SHA256'
    TLS_DH_ANON_WITH_AES_256_CBC_SHA256 = 109
    ietfNames[109] = 'TLS_DH_ANON_WITH_AES_256_CBC_SHA256'
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 156
    ietfNames[156] = 'TLS_RSA_WITH_AES_128_GCM_SHA256'
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 157
    ietfNames[157] = 'TLS_RSA_WITH_AES_256_GCM_SHA384'
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 158
    ietfNames[158] = 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 159
    ietfNames[159] = 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 162
    ietfNames[162] = 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256'
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 163
    ietfNames[163] = 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384'
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 164
    ietfNames[164] = 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256'
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 165
    ietfNames[165] = 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384'
    TLS_DH_ANON_WITH_AES_128_GCM_SHA256 = 166
    ietfNames[166] = 'TLS_DH_ANON_WITH_AES_128_GCM_SHA256'
    TLS_DH_ANON_WITH_AES_256_GCM_SHA384 = 167
    ietfNames[167] = 'TLS_DH_ANON_WITH_AES_256_GCM_SHA384'
    TLS_RSA_WITH_AES_128_CCM = 49308
    ietfNames[49308] = 'TLS_RSA_WITH_AES_128_CCM'
    TLS_RSA_WITH_AES_256_CCM = 49309
    ietfNames[49309] = 'TLS_RSA_WITH_AES_256_CCM'
    TLS_DHE_RSA_WITH_AES_128_CCM = 49310
    ietfNames[49310] = 'TLS_DHE_RSA_WITH_AES_128_CCM'
    TLS_DHE_RSA_WITH_AES_256_CCM = 49311
    ietfNames[49311] = 'TLS_DHE_RSA_WITH_AES_256_CCM'
    TLS_RSA_WITH_AES_128_CCM_8 = 49312
    ietfNames[49312] = 'TLS_RSA_WITH_AES_128_CCM_8'
    TLS_RSA_WITH_AES_256_CCM_8 = 49313
    ietfNames[49313] = 'TLS_RSA_WITH_AES_256_CCM_8'
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = 49314
    ietfNames[49314] = 'TLS_DHE_RSA_WITH_AES_128_CCM_8'
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = 49315
    ietfNames[49315] = 'TLS_DHE_RSA_WITH_AES_256_CCM_8'
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 255
    ietfNames[255] = 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'
    TLS_AES_128_GCM_SHA256 = 4865
    ietfNames[4865] = 'TLS_AES_128_GCM_SHA256'
    TLS_AES_256_GCM_SHA384 = 4866
    ietfNames[4866] = 'TLS_AES_256_GCM_SHA384'
    TLS_CHACHA20_POLY1305_SHA256 = 4867
    ietfNames[4867] = 'TLS_CHACHA20_POLY1305_SHA256'
    TLS_AES_128_CCM_SHA256 = 4868
    ietfNames[4868] = 'TLS_AES_128_CCM_SHA256'
    TLS_AES_128_CCM_8_SHA256 = 4869
    ietfNames[4869] = 'TLS_AES_128_CCM_8_SHA256'
    TLS_FALLBACK_SCSV = 22016
    ietfNames[22016] = 'TLS_FALLBACK_SCSV'
    TLS_ECDH_ECDSA_WITH_NULL_SHA = 49153
    ietfNames[49153] = 'TLS_ECDH_ECDSA_WITH_NULL_SHA'
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 49154
    ietfNames[49154] = 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA'
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 49155
    ietfNames[49155] = 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA'
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 49156
    ietfNames[49156] = 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA'
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 49157
    ietfNames[49157] = 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA'
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = 49158
    ietfNames[49158] = 'TLS_ECDHE_ECDSA_WITH_NULL_SHA'
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 49159
    ietfNames[49159] = 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA'
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 49160
    ietfNames[49160] = 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA'
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 49161
    ietfNames[49161] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 49162
    ietfNames[49162] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'
    TLS_ECDH_RSA_WITH_NULL_SHA = 49163
    ietfNames[49163] = 'TLS_ECDH_RSA_WITH_NULL_SHA'
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 49164
    ietfNames[49164] = 'TLS_ECDH_RSA_WITH_RC4_128_SHA'
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 49165
    ietfNames[49165] = 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA'
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 49166
    ietfNames[49166] = 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA'
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 49167
    ietfNames[49167] = 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA'
    TLS_ECDHE_RSA_WITH_NULL_SHA = 49168
    ietfNames[49168] = 'TLS_ECDHE_RSA_WITH_NULL_SHA'
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 49169
    ietfNames[49169] = 'TLS_ECDHE_RSA_WITH_RC4_128_SHA'
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 49170
    ietfNames[49170] = 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 49171
    ietfNames[49171] = 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 49172
    ietfNames[49172] = 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    TLS_ECDH_ANON_WITH_NULL_SHA = 49173
    ietfNames[49173] = 'TLS_ECDH_ANON_WITH_NULL_SHA'
    TLS_ECDH_ANON_WITH_RC4_128_SHA = 49174
    ietfNames[49174] = 'TLS_ECDH_ANON_WITH_RC4_128_SHA'
    TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA = 49175
    ietfNames[49175] = 'TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA'
    TLS_ECDH_ANON_WITH_AES_128_CBC_SHA = 49176
    ietfNames[49176] = 'TLS_ECDH_ANON_WITH_AES_128_CBC_SHA'
    TLS_ECDH_ANON_WITH_AES_256_CBC_SHA = 49177
    ietfNames[49177] = 'TLS_ECDH_ANON_WITH_AES_256_CBC_SHA'
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 49178
    ietfNames[49178] = 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA'
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 49179
    ietfNames[49179] = 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA'
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 49180
    ietfNames[49180] = 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA'
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 49181
    ietfNames[49181] = 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA'
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 49182
    ietfNames[49182] = 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA'
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 49183
    ietfNames[49183] = 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA'
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 49184
    ietfNames[49184] = 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA'
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 49185
    ietfNames[49185] = 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA'
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 49186
    ietfNames[49186] = 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA'
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 49187
    ietfNames[49187] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 49188
    ietfNames[49188] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 49189
    ietfNames[49189] = 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256'
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 49190
    ietfNames[49190] = 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384'
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 49191
    ietfNames[49191] = 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 49192
    ietfNames[49192] = 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 49193
    ietfNames[49193] = 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256'
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 49194
    ietfNames[49194] = 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384'
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 49195
    ietfNames[49195] = 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 49196
    ietfNames[49196] = 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 49197
    ietfNames[49197] = 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256'
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 49198
    ietfNames[49198] = 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384'
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 49199
    ietfNames[49199] = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 49200
    ietfNames[49200] = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 49201
    ietfNames[49201] = 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256'
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 49202
    ietfNames[49202] = 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384'
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00 = 52385
    ietfNames[52385] = 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00'
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00 = 52386
    ietfNames[52386] = 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00'
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00 = 52387
    ietfNames[52387] = 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00'
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52392
    ietfNames[52392] = 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 52393
    ietfNames[52393] = 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52394
    ietfNames[52394] = 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 49324
    ietfNames[49324] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM'
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 49325
    ietfNames[49325] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM'
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 49326
    ietfNames[49326] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8'
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 49327
    ietfNames[49327] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8'
    tripleDESSuites = []
    tripleDESSuites.append(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)
    tripleDESSuites.append(TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA)
    aes128Suites = []
    aes128Suites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_RSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_ECDH_ANON_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DH_DSS_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DHE_DSS_WITH_AES_128_CBC_SHA)
    aes128Suites.append(TLS_DH_DSS_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256)
    aes128Suites.append(TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA)
    aes256Suites = []
    aes256Suites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_RSA_WITH_AES_256_CBC_SHA256)
    aes256Suites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
    aes256Suites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA256)
    aes256Suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)
    aes256Suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384)
    aes256Suites.append(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384)
    aes256Suites.append(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
    aes256Suites.append(TLS_ECDH_ANON_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DH_DSS_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DHE_DSS_WITH_AES_256_CBC_SHA)
    aes256Suites.append(TLS_DH_DSS_WITH_AES_256_CBC_SHA256)
    aes256Suites.append(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256)
    aes256Suites.append(TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA)
    aes128GcmSuites = []
    aes128GcmSuites.append(TLS_RSA_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_DH_ANON_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256)
    aes128GcmSuites.append(TLS_DH_DSS_WITH_AES_128_GCM_SHA256)
    aes256GcmSuites = []
    aes256GcmSuites.append(TLS_RSA_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_DH_ANON_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384)
    aes256GcmSuites.append(TLS_DH_DSS_WITH_AES_256_GCM_SHA384)
    aes128Ccm_8Suites = []
    aes128Ccm_8Suites.append(TLS_RSA_WITH_AES_128_CCM_8)
    aes128Ccm_8Suites.append(TLS_DHE_RSA_WITH_AES_128_CCM_8)
    aes128Ccm_8Suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
    aes128Ccm_8Suites.append(TLS_AES_128_CCM_8_SHA256)
    aes128CcmSuites = []
    aes128CcmSuites.append(TLS_RSA_WITH_AES_128_CCM)
    aes128CcmSuites.append(TLS_DHE_RSA_WITH_AES_128_CCM)
    aes128CcmSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CCM)
    aes128CcmSuites.append(TLS_AES_128_CCM_SHA256)
    aes256Ccm_8Suites = []
    aes256Ccm_8Suites.append(TLS_RSA_WITH_AES_256_CCM_8)
    aes256Ccm_8Suites.append(TLS_DHE_RSA_WITH_AES_256_CCM_8)
    aes256Ccm_8Suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8)
    aes256CcmSuites = []
    aes256CcmSuites.append(TLS_RSA_WITH_AES_256_CCM)
    aes256CcmSuites.append(TLS_DHE_RSA_WITH_AES_256_CCM)
    aes256CcmSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CCM)
    chacha20draft00Suites = []
    chacha20draft00Suites.append(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00)
    chacha20draft00Suites.append(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00)
    chacha20draft00Suites.append(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00)
    chacha20Suites = []
    chacha20Suites.append(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
    chacha20Suites.append(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
    chacha20Suites.append(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
    chacha20Suites.append(TLS_CHACHA20_POLY1305_SHA256)
    rc4Suites = []
    rc4Suites.append(TLS_ECDHE_RSA_WITH_RC4_128_SHA)
    rc4Suites.append(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
    rc4Suites.append(TLS_ECDH_ECDSA_WITH_RC4_128_SHA)
    rc4Suites.append(TLS_ECDH_RSA_WITH_RC4_128_SHA)
    rc4Suites.append(TLS_DH_ANON_WITH_RC4_128_MD5)
    rc4Suites.append(TLS_RSA_WITH_RC4_128_SHA)
    rc4Suites.append(TLS_RSA_WITH_RC4_128_MD5)
    rc4Suites.append(TLS_ECDH_ANON_WITH_RC4_128_SHA)
    nullSuites = []
    nullSuites.append(TLS_RSA_WITH_NULL_MD5)
    nullSuites.append(TLS_RSA_WITH_NULL_SHA)
    nullSuites.append(TLS_RSA_WITH_NULL_SHA256)
    nullSuites.append(TLS_ECDHE_ECDSA_WITH_NULL_SHA)
    nullSuites.append(TLS_ECDH_ECDSA_WITH_NULL_SHA)
    nullSuites.append(TLS_ECDH_RSA_WITH_NULL_SHA)
    nullSuites.append(TLS_ECDHE_RSA_WITH_NULL_SHA)
    nullSuites.append(TLS_ECDH_ANON_WITH_NULL_SHA)
    shaSuites = []
    shaSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_RC4_128_SHA)
    shaSuites.append(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_DHE_DSS_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_DHE_DSS_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_DH_DSS_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_DH_DSS_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_RSA_WITH_NULL_SHA)
    shaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
    shaSuites.append(TLS_ECDHE_ECDSA_WITH_NULL_SHA)
    shaSuites.append(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_ECDH_ECDSA_WITH_RC4_128_SHA)
    shaSuites.append(TLS_ECDH_ECDSA_WITH_NULL_SHA)
    shaSuites.append(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_ECDH_RSA_WITH_RC4_128_SHA)
    shaSuites.append(TLS_ECDH_RSA_WITH_NULL_SHA)
    shaSuites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_ECDHE_RSA_WITH_RC4_128_SHA)
    shaSuites.append(TLS_ECDHE_RSA_WITH_NULL_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_AES_256_CBC_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_AES_128_CBC_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_RC4_128_SHA)
    shaSuites.append(TLS_ECDH_ANON_WITH_NULL_SHA)
    sha256Suites = []
    sha256Suites.append(TLS_RSA_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_RSA_WITH_AES_256_CBC_SHA256)
    sha256Suites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
    sha256Suites.append(TLS_RSA_WITH_NULL_SHA256)
    sha256Suites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA256)
    sha256Suites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256)
    sha256Suites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
    sha384Suites = []
    sha384Suites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)
    sha384Suites.append(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384)
    sha384Suites.append(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384)
    sha384Suites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
    sha384Suites.append(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384)
    sha384Suites.append(TLS_DH_DSS_WITH_AES_256_GCM_SHA384)
    streamSuites = []
    streamSuites.extend(rc4Suites)
    streamSuites.extend(nullSuites)
    aeadSuites = []
    aeadSuites.extend(aes128GcmSuites)
    aeadSuites.extend(aes256GcmSuites)
    aeadSuites.extend(aes128CcmSuites)
    aeadSuites.extend(aes128Ccm_8Suites)
    aeadSuites.extend(aes256CcmSuites)
    aeadSuites.extend(aes256Ccm_8Suites)
    aeadSuites.extend(chacha20Suites)
    aeadSuites.extend(chacha20draft00Suites)
    sha384PrfSuites = []
    sha384PrfSuites.extend(sha384Suites)
    sha384PrfSuites.extend(aes256GcmSuites)
    md5Suites = []
    md5Suites.append(TLS_DH_ANON_WITH_RC4_128_MD5)
    md5Suites.append(TLS_RSA_WITH_RC4_128_MD5)
    md5Suites.append(TLS_RSA_WITH_NULL_MD5)
    ssl3Suites = []
    ssl3Suites.extend(shaSuites)
    ssl3Suites.extend(md5Suites)
    tls12Suites = []
    tls12Suites.extend(sha256Suites)
    tls12Suites.extend(sha384Suites)
    tls12Suites.extend(aeadSuites)
    sha256PrfSuites = []
    sha256PrfSuites.extend(tls12Suites)
    for i in sha384PrfSuites:
        sha256PrfSuites.remove(i)
    tls13Suites = []
    tls13Suites.append(TLS_AES_256_GCM_SHA384)
    tls12Suites.remove(TLS_AES_256_GCM_SHA384)
    tls13Suites.append(TLS_AES_128_GCM_SHA256)
    tls12Suites.remove(TLS_AES_128_GCM_SHA256)
    tls13Suites.append(TLS_CHACHA20_POLY1305_SHA256)
    tls12Suites.remove(TLS_CHACHA20_POLY1305_SHA256)
    tls13Suites.append(TLS_AES_128_CCM_SHA256)
    tls12Suites.remove(TLS_AES_128_CCM_SHA256)
    tls13Suites.append(TLS_AES_128_CCM_8_SHA256)
    tls12Suites.remove(TLS_AES_128_CCM_8_SHA256)

    @staticmethod
    def filterForVersion(suites, minVersion, maxVersion):
        """Return a copy of suites without ciphers incompatible with version"""
        return [s for s in suites if CipherSuite._getMinVersion(s) <= maxVersion
                and CipherSuite._getMaxVersion(s) >= minVersion]

    @staticmethod
    def filter_for_certificate(suites, cert_chain):
        """Return a copy of suites without ciphers incompatible with the cert.
        """
        if not cert_chain:
            return suites
        key_type = cert_chain.getKeyType()
        return [s for s in suites if CipherSuite._getKeyType(s) == key_type]

    @staticmethod
    def filter_for_prfs(suites, prfs):
        """Return a copy of suites without ciphers incompatible with the
        specified prfs (sha256 or sha384)"""
        return [s for s in suites if CipherSuite._getPRFHash(s) in prfs]

    @classmethod
    def getTLS13Suites(cls, settings, version=None):
        """Return cipher suites that are TLS 1.3 specific."""
        suites = cls.tls13Suites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    srpSuites = []
    srpSuites.append(TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
    srpSuites.append(TLS_SRP_SHA_WITH_AES_128_CBC_SHA)
    srpSuites.append(TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA)

    @classmethod
    def getSrpSuites(cls, settings, version=None):
        """Return SRP cipher suites matching settings"""
        suites = cls.srpSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    srpCertSuites = []
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA)
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA)
    srpCertSuites.append(TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)

    @classmethod
    def getSrpCertSuites(cls, settings, version=None):
        """Return SRP cipher suites that use server certificates"""
        suites = cls.srpCertSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    srpDsaSuites = []
    srpDsaSuites.append(TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA)
    srpDsaSuites.append(TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA)
    srpDsaSuites.append(TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA)

    @classmethod
    def getSrpDsaSuites(cls, settings, version=None):
        """Return SRP DSA cipher suites that use server certificates"""
        suites = cls.srpDsaSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    srpAllSuites = srpSuites + srpCertSuites

    @classmethod
    def getSrpAllSuites(cls, settings, version=None):
        """Return all SRP cipher suites matching settings"""
        suites = cls.srpAllSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    certSuites = []
    certSuites.append(TLS_RSA_WITH_AES_256_GCM_SHA384)
    certSuites.append(TLS_RSA_WITH_AES_128_GCM_SHA256)
    certSuites.append(TLS_RSA_WITH_AES_256_CCM)
    certSuites.append(TLS_RSA_WITH_AES_128_CCM)
    certSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA256)
    certSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA256)
    certSuites.append(TLS_RSA_WITH_AES_256_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_AES_128_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_AES_256_CCM_8)
    certSuites.append(TLS_RSA_WITH_AES_128_CCM_8)
    certSuites.append(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    certSuites.append(TLS_RSA_WITH_RC4_128_SHA)
    certSuites.append(TLS_RSA_WITH_RC4_128_MD5)
    certSuites.append(TLS_RSA_WITH_NULL_MD5)
    certSuites.append(TLS_RSA_WITH_NULL_SHA)
    certSuites.append(TLS_RSA_WITH_NULL_SHA256)

    @classmethod
    def getCertSuites(cls, settings, version=None):
        """Return ciphers with RSA authentication matching settings"""
        suites = cls.certSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    dheCertSuites = []
    dheCertSuites.append(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
    dheCertSuites.append(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_256_CCM)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_128_CCM)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_256_CCM_8)
    dheCertSuites.append(TLS_DHE_RSA_WITH_AES_128_CCM_8)
    dheCertSuites.append(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)

    @classmethod
    def getDheCertSuites(cls, settings, version=None):
        """Provide authenticated DHE ciphersuites matching settings"""
        suites = cls.dheCertSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    ecdheCertSuites = []
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_RC4_128_SHA)
    ecdheCertSuites.append(TLS_ECDHE_RSA_WITH_NULL_SHA)

    @classmethod
    def getEcdheCertSuites(cls, settings, version=None):
        """Provide authenticated ECDHE ciphersuites matching settings"""
        suites = cls.ecdheCertSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    certAllSuites = srpCertSuites + certSuites + dheCertSuites + ecdheCertSuites
    ecdheEcdsaSuites = []
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CCM)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CCM)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
    ecdheEcdsaSuites.append(TLS_ECDHE_ECDSA_WITH_NULL_SHA)

    @classmethod
    def getEcdsaSuites(cls, settings, version=None):
        """Provide ECDSA authenticated ciphersuites matching settings"""
        suites = cls.ecdheEcdsaSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    dheDsaSuites = []
    dheDsaSuites.append(TLS_DHE_DSS_WITH_AES_256_GCM_SHA384)
    dheDsaSuites.append(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256)
    dheDsaSuites.append(TLS_DHE_DSS_WITH_AES_256_CBC_SHA256)
    dheDsaSuites.append(TLS_DHE_DSS_WITH_AES_128_CBC_SHA256)
    dheDsaSuites.append(TLS_DHE_DSS_WITH_AES_256_CBC_SHA)
    dheDsaSuites.append(TLS_DHE_DSS_WITH_AES_128_CBC_SHA)
    dheDsaSuites.append(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)

    @classmethod
    def getDheDsaSuites(cls, settings, version=None):
        """Provide DSA authenticated ciphersuites matching settings"""
        suites = cls.dheDsaSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    anonSuites = []
    anonSuites.append(TLS_DH_ANON_WITH_AES_256_GCM_SHA384)
    anonSuites.append(TLS_DH_ANON_WITH_AES_128_GCM_SHA256)
    anonSuites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA256)
    anonSuites.append(TLS_DH_ANON_WITH_AES_256_CBC_SHA)
    anonSuites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA256)
    anonSuites.append(TLS_DH_ANON_WITH_AES_128_CBC_SHA)
    anonSuites.append(TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA)
    anonSuites.append(TLS_DH_ANON_WITH_RC4_128_MD5)

    @classmethod
    def getAnonSuites(cls, settings, version=None):
        """Provide anonymous DH ciphersuites matching settings"""
        suites = cls.anonSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    dhAllSuites = dheCertSuites + anonSuites + dheDsaSuites
    ecdhAnonSuites = []
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_AES_256_CBC_SHA)
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_AES_128_CBC_SHA)
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA)
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_RC4_128_SHA)
    ecdhAnonSuites.append(TLS_ECDH_ANON_WITH_NULL_SHA)

    @classmethod
    def getEcdhAnonSuites(cls, settings, version=None):
        """Provide anonymous ECDH ciphersuites matching settings"""
        suites = cls.ecdhAnonSuites
        if settings.cipherNames:
            suites = [s for s in suites if cls._getCipherName(s) in settings.cipherNames]
        return cls.filterForVersion(suites, settings.minVersion, settings.maxVersion)
    ecdhAllSuites = ecdheEcdsaSuites + ecdheCertSuites + ecdhAnonSuites

    @staticmethod
    def canonicalCipherName(ciphersuite):
        """Return the canonical name of the cipher whose number is provided."""
        if ciphersuite in CipherSuite.ietfNames:
            return CipherSuite.ietfNames[ciphersuite]
        else:
            return None

    @staticmethod
    def canonicalMacName(ciphersuite):
        """Return the canonical name of the MAC whose number is provided."""
        name = CipherSuite.canonicalCipherName(ciphersuite)
        if name:
            if "MD5" in name:
                return "MD5"
            elif "SHA" in name:
                if "SHA384" in name:
                    return "SHA384"
                elif "SHA256" in name:
                    return "SHA256"
                else:
                    return "SHA"
        return None

class Fault:
    badUsername = 101
    badPassword = 102
    badA = 103
    clientSrpFaults = list(range(101, 104))
    badVerifyMessage = 601
    clientCertFaults = list(range(601, 602))
    badPremasterPadding = 501
    shortPremasterSecret = 502
    clientNoAuthFaults = list(range(501, 503))
    badB = 201
    serverFaults = list(range(201, 202))
    badFinished = 300
    badMAC = 301
    badPadding = 302
    genericFaults = list(range(300, 303))
    faultAlerts = {badUsername: (AlertDescription.unknown_psk_identity, AlertDescription.bad_record_mac), badPassword: (AlertDescription.bad_record_mac,), badA: (AlertDescription.illegal_parameter,), badPremasterPadding: (AlertDescription.bad_record_mac,), shortPremasterSecret: (AlertDescription.bad_record_mac,), badVerifyMessage: (AlertDescription.decrypt_error,), badFinished: (AlertDescription.decrypt_error,), badMAC: (AlertDescription.bad_record_mac,), badPadding: (AlertDescription.bad_record_mac,)}
    faultNames = {badUsername: 'bad username', badPassword: 'bad password', badA: 'bad A', badPremasterPadding: 'bad premaster padding', shortPremasterSecret: 'short premaster secret', badVerifyMessage: 'bad verify message', badFinished: 'bad finished message', badMAC: 'bad MAC', badPadding: 'bad padding'}
