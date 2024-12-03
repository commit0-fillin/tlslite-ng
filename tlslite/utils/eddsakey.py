"""Abstract class for EdDSA."""

class EdDSAKey(object):
    """This is an abstract base class for EdDSA keys.

    Particular implementations of EdDSA keys, such as
    :py:class:`~.python_eddsakey.Python_EdDSAKey`
    ... more coming
    inherit from this.

    To create or parse an EdDSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    :py:class:`~tlslite.utils.keyfactory`.
    """

    def __len__(self):
        """Return the size of the order of the curve of this key, in bits.

        :rtype: int
        """
        raise NotImplementedError()

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        :rtype: bool
        """
        return hasattr(self, 'private_key') and self.private_key is not None

    def hashAndSign(self, data, rsaScheme=None, hAlg=None, sLen=None):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component. It performs
        a signature on the passed-in data with selected hash algorithm.

        :type bytes: bytes-like object
        :param bytes: The value which will be hashed and signed.

        :type rsaScheme: str
        :param rsaScheme: Ignored, present for API compatibility with RSA

        :type hAlg: str
        :param hAlg: Ignored, present for API compatibility with RSA/ECDSA

        :type sLen: int
        :param sLen: Ignored, present for API compatibility with RSA

        :rtype: bytearray
        :returns: An EdDSA signature on the passed-in data.
        """
        if not self.hasPrivateKey():
            raise ValueError("Private key is required for signing")
        
        # EdDSA doesn't use a separate hash function, it's part of the algorithm
        signature = self.private_key.sign(data)
        return bytearray(signature)

    def hashAndVerify(self, sig_bytes, data, rsaScheme=None, hAlg=None, sLen=None):
        """Hash and verify the passed-in bytes with the signature.

        This verifies an EdDSA signature on the passed-in data
        with the implicit hash algorithm.

        :type sigBytes: bytearray
        :param sigBytes: An EdDSA signature

        :type bytes: str or bytearray
        :param bytes: The value which will be hashed and verified.

        :type rsaScheme: str
        :param rsaScheme: Ignored, present for API compatibility with RSA

        :type hAlg: str
        :param hAlg: Ignored, present for API compatibility with RSA

        :type sLen: int
        :param sLen: Ignored, present for API compatibility with RSA

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        try:
            # EdDSA doesn't use a separate hash function, it's part of the algorithm
            return self.public_key.verify(sig_bytes, data)
        except:
            return False

    @staticmethod
    def sign(self, bytes, padding=None, hashAlg='sha1', saltLen=None):
        """Sign the passed-in bytes.

        Note: this method is unsupported for EdDSA keys, as pre-hash
        signatures are unsupported. Use hashAndSign to perform the
        Pure EdDSA signature creation.

        :type bytes: bytearray
        :param bytes: Ignored

        :type padding: str
        :param padding: Ignored

        :type hashAlg: str
        :param hashAlg: Ignored

        :type saltLen: int
        :param saltLen: Ignored
        """
        raise NotImplementedError("EdDSA does not support pre-hash signatures. Use hashAndSign instead.")

    @staticmethod
    def verify(self, sigBytes, bytes, padding=None, hashAlg=None, saltLen=None):
        """Verify the passed-in bytes with the signature.

        Note: this method is unsupported for EdDSA keys, as pre-hash
        signatures are unsupported. Use hashAndVerify to perform the
        Pure EdDSA verification.

        :type sigBytes: bytearray
        :param sigBytes: Ignored

        :type bytes: bytearray
        :param bytes: Ignored

        :type padding: str
        :param padding: Ignored
        """
        raise NotImplementedError("EdDSA does not support pre-hash signatures. Use hashAndVerify instead.")

    def acceptsPassword(self):
        """Return True if the write() method accepts a password for use
        in encrypting the private key.

        :rtype: bool
        """
        return True

    def write(self, password=None):
        """Return a string containing the key.

        :rtype: str
        :returns: A string describing the key, in whichever format (PEM)
            is native to the implementation.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption

        if self.hasPrivateKey():
            if password:
                encryption = BestAvailableEncryption(password.encode())
            else:
                encryption = NoEncryption()
            return self.private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ).decode()
        else:
            return self.public_key.public_bytes(
                encoding=Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

    @staticmethod
    def generate(bits):
        """Generate a new key with the specified curve.

        :rtype: ~tlslite.utils.EdDSAKey.EdDSAKey
        """
        from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
        from tlslite.utils.python_eddsakey import Python_EdDSAKey

        if bits == 256:
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif bits == 456:
            private_key = ed448.Ed448PrivateKey.generate()
        else:
            raise ValueError("Unsupported key size. Use 256 for Ed25519 or 456 for Ed448.")

        return Python_EdDSAKey(private_key)
