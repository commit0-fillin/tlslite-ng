"""Abstract class for DSA."""

class DSAKey(object):
    """This is an abstract base class for DSA keys.

    Particular implementations of DSA keys, such as
    :py:class:`~.python_dsakey.Python_DSAKey`
    ... more coming
    inherit from this.

    To create or parse an DSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    :py:class:`~tlslite.utils.keyfactory`.
    """

    def __init__(self, p, q, g, x, y):
        """Create a new DSA key.
        :type p: int
        :param p: domain parameter, prime num defining Gaolis Field
        :type q: int
        :param q: domain parameter, prime factor of p-1
        :type g: int
        :param g: domain parameter, generator of q-order cyclic group GP(p)
        :type x: int
        :param x: private key
        :type y: int
        :param y: public key
        """
        raise NotImplementedError()

    def __len__(self):
        """Return the size of the order of the curve of this key, in bits.

        :rtype: int
        """
        raise NotImplementedError()

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        :rtype: bool
        """
        return self.x is not None

    def hashAndSign(self, data, hAlg):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component and
        global parameters. It performs a signature on the passed-in data
        with selected hash algorithm.

        :type data: str
        :param data: The data which will be hashed and signed.

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used to hash data

        :rtype: bytearray
        :returns: An DSA signature on the passed-in data.
        """
        if not self.hasPrivateKey():
            raise ValueError("Private key is required for signing")

        import hashlib
        import random
        from .compat import compatHMAC

        # Hash the data
        hash_obj = hashlib.new(hAlg)
        hash_obj.update(compatHMAC(data))
        hashed = hash_obj.digest()

        # Generate k (random number) and r
        k = random.randrange(1, self.q)
        r = pow(self.g, k, self.p) % self.q

        # Calculate s
        k_inv = pow(k, -1, self.q)
        s = (k_inv * (int.from_bytes(hashed, 'big') + self.x * r)) % self.q

        # Convert r and s to bytearray
        signature = bytearray((r).to_bytes((r.bit_length() + 7) // 8, 'big'))
        signature += bytearray((s).to_bytes((s.bit_length() + 7) // 8, 'big'))

        return signature

    def hashAndVerify(self, signature, data, hAlg='sha1'):
        """Hash and verify the passed-in bytes with signature.

        :type signature: ASN1 bytearray
        :param signature: the r, s dsa signature

        :type data: str
        :param data: The data which will be hashed and verified.

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used to hash data

        :rtype: bool
        :returns: return True if verification is OK.
        """
        import hashlib
        from .compat import compatHMAC

        # Extract r and s from signature
        sig_len = len(signature) // 2
        r = int.from_bytes(signature[:sig_len], 'big')
        s = int.from_bytes(signature[sig_len:], 'big')

        # Check if r and s are in the correct range
        if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
            return False

        # Hash the data
        hash_obj = hashlib.new(hAlg)
        hash_obj.update(compatHMAC(data))
        hashed = int.from_bytes(hash_obj.digest(), 'big')

        # Compute w, u1, and u2
        w = pow(s, -1, self.q)
        u1 = (hashed * w) % self.q
        u2 = (r * w) % self.q

        # Compute v
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q

        # Verify the signature
        return v == r

    @staticmethod
    def generate(L, N):
        """Generate new key given by bit lengths L, N.

        :type L: int
        :param L: length of parameter p in bits

        :type N: int
        :param N: length of parameter q in bits

        :rtype: DSAkey
        :returns: DSAkey(domain parameters, private key, public key)
        """
        import random

        # Generate p and q
        p, q = DSAKey.generate_qp(L, N)

        # Generate g
        h = 2
        while True:
            g = pow(h, (p - 1) // q, p)
            if g > 1:
                break
            h += 1

        # Generate private key x
        x = random.randrange(1, q)

        # Generate public key y
        y = pow(g, x, p)

        return DSAKey(p, q, g, x, y)

    @staticmethod
    def generate_qp(L, N):
        """Generate new (p, q) given by bit lengths L, N.

        :type L: int
        :param L: length of parameter p in bits

        :type N: int
        :param N: length of parameter q in bits

        :rtype: (int, int)
        :returns: new p and q key parameters
        """
        import random
        from .cryptomath import isPrime, getRandomPrime

        # Generate q
        q = getRandomPrime(N)

        # Generate p
        while True:
            x = random.getrandbits(L - N)
            p = q * x + 1
            if p.bit_length() == L and isPrime(p):
                break

        return p, q
