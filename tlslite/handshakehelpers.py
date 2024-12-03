"""Class with various handshake helpers."""
from .extensions import PaddingExtension, PreSharedKeyExtension
from .utils.cryptomath import derive_secret, secureHMAC, HKDF_expand_label
from .utils.constanttime import ct_compare_digest
from .errors import TLSIllegalParameterException

class HandshakeHelpers(object):
    """
    This class encapsulates helper functions to be used with a TLS handshake.
    """

    @staticmethod
    def alignClientHelloPadding(clientHello):
        """
        Align ClientHello using the Padding extension to 512 bytes at least.

        :param ClientHello clientHello: ClientHello to be aligned
        """
        current_length = len(clientHello.write())
        target_length = 512
        if current_length < target_length:
            padding_length = target_length - current_length
            padding_extension = PaddingExtension().create(padding_length)
            clientHello.extensions.append(padding_extension)

    @staticmethod
    def _calc_binder(prf, psk, handshake_hash, external=True):
        """
        Calculate the binder value for a given HandshakeHash (that includes
        a truncated client hello already)
        """
        if external:
            label = b"ext binder"
        else:
            label = b"res binder"
        
        binder_key = derive_secret(psk, label, None, prf)
        binder = secureHMAC(binder_key, handshake_hash.digest(prf), prf)
        return binder

    @staticmethod
    def calc_res_binder_psk(iden, res_master_secret, tickets):
        """Calculate PSK associated with provided ticket identity."""
        for ticket in tickets:
            if ticket.ticket == iden:
                psk = derive_secret(res_master_secret, b"resumption", 
                                    ticket.nonce, ticket.prf)
                return psk
        return None

    @staticmethod
    def update_binders(client_hello, handshake_hashes, psk_configs, tickets=None, res_master_secret=None):
        """
        Sign the Client Hello using TLS 1.3 PSK binders.

        note: the psk_configs should be in the same order as the ones in the
        PreSharedKeyExtension extension (extra ones are ok)

        :param client_hello: ClientHello to sign
        :param handshake_hashes: hashes of messages exchanged so far
        :param psk_configs: PSK identities and secrets
        :param tickets: optional list of tickets received from server
        :param bytearray res_master_secret: secret associated with the
            tickets
        """
        psk_ext = client_hello.getExtension(PreSharedKeyExtension.extType)
        if not psk_ext:
            return

        binders = []
        for identity, (psk, prf, external) in zip(psk_ext.identities, psk_configs):
            if external:
                binders.append(HandshakeHelpers._calc_binder(prf, psk, handshake_hashes.copy()))
            else:
                psk = HandshakeHelpers.calc_res_binder_psk(identity.identity, res_master_secret, tickets)
                if psk:
                    binders.append(HandshakeHelpers._calc_binder(prf, psk, handshake_hashes.copy(), external=False))
                else:
                    raise TLSInternalError("Can't calculate binder for unknown PSK")

        psk_ext.binders = binders

    @staticmethod
    def verify_binder(client_hello, handshake_hashes, position, secret, prf, external=True):
        """Verify the PSK binder value in client hello.

        :param client_hello: ClientHello to verify
        :param handshake_hashes: hashes of messages exchanged so far
        :param position: binder at which position should be verified
        :param secret: the secret PSK
        :param prf: name of the hash used as PRF
        """
        psk_ext = client_hello.getExtension(PreSharedKeyExtension.extType)
        if not psk_ext:
            raise TLSIllegalParameterException("No PSK extension in ClientHello")

        if position >= len(psk_ext.binders):
            raise TLSIllegalParameterException("Invalid binder position")

        binder = psk_ext.binders[position]
        calculated_binder = HandshakeHelpers._calc_binder(prf, secret, handshake_hashes.copy(), external)

        if not ct_compare_digest(binder, calculated_binder):
            raise TLSIllegalParameterException("Binder does not verify")
