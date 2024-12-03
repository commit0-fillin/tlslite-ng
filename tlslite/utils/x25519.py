"""Handling X25519 and X448 curve based key agreement protocol."""
from .cryptomath import bytesToNumber, numberToByteArray, divceil

def decodeUCoordinate(u, bits):
    """Function to decode the public U coordinate of X25519-family curves."""
    u_list = list(u)
    if bits == 255:
        u_list[-1] &= 127
    elif bits == 448:
        u_list[0] &= 252
    return bytesToNumber(bytearray(u_list))

def decodeScalar22519(k):
    """Function to decode the private K parameter of the x25519 function."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytesToNumber(k)

def decodeScalar448(k):
    """Function to decode the private K parameter of the X448 function."""
    k = bytearray(k)
    k[0] &= 252
    k[55] |= 128
    return bytesToNumber(k)

def cswap(swap, x_2, x_3):
    """Conditional swap function."""
    dummy = swap * (x_2 ^ x_3)
    x_2 ^= dummy
    x_3 ^= dummy
    return x_2, x_3
X25519_G = numberToByteArray(9, 32, endian='little')
X25519_ORDER_SIZE = 32

def x25519(k, u):
    """
    Perform point multiplication on X25519 curve.

    :type k: bytearray
    :param k: random secret value (multiplier), should be 32 byte long

    :type u: bytearray
    :param u: curve generator or the other party key share

    :rtype: bytearray
    """
    x1 = decodeUCoordinate(u, 255)
    x2 = 1
    z2 = 0
    x3 = x1
    z3 = 1
    swap = 0

    k = decodeScalar22519(k)

    for t in range(255, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = kt

        A = x2 + z2
        AA = A * A
        B = x2 - z2
        BB = B * B
        E = AA - BB
        C = x3 + z3
        D = x3 - z3
        DA = D * A
        CB = C * B
        x3 = pow((DA + CB) % p, 2, p)
        z3 = x1 * pow((DA - CB) % p, 2, p) % p
        x2 = (AA * BB) % p
        z2 = E * (AA + a24 * E) % p

    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    return numberToByteArray(x2 * pow(z2, p - 2, p) % p, X25519_ORDER_SIZE)
X448_G = numberToByteArray(5, 56, endian='little')
X448_ORDER_SIZE = 56
p = 2**255 - 19  # Characteristic of the X25519 curve

def x448(k, u):
    """
    Perform point multiplication on X448 curve.

    :type k: bytearray
    :param k: random secret value (multiplier), should be 56 bytes long

    :type u: bytearray
    :param u: curve generator or the other party key share

    :rtype: bytearray
    """
    return _x25519_generic(k, u, 448, 39081, 2**448 - 2**224 - 1)

def _x25519_generic(k, u, bits, a24, p):
    """Generic Montgomery ladder implementation of the x25519 algorithm."""
    x1 = decodeUCoordinate(u, bits)
    x2 = 1
    z2 = 0
    x3 = x1
    z3 = 1
    swap = 0

    k = decodeScalar448(k) if bits == 448 else decodeScalar22519(k)

    for t in range(bits - 1, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = kt

        A = (x2 + z2) % p
        AA = pow(A, 2, p)
        B = (x2 - z2) % p
        BB = pow(B, 2, p)
        E = (AA - BB) % p
        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x3 = pow((DA + CB) % p, 2, p)
        z3 = (x1 * pow((DA - CB) % p, 2, p)) % p
        x2 = (AA * BB) % p
        z2 = (E * ((AA + a24 * E) % p)) % p

    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    return numberToByteArray((x2 * pow(z2, p - 2, p)) % p, X448_ORDER_SIZE if bits == 448 else X25519_ORDER_SIZE)
