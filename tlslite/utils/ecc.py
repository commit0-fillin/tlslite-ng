"""Methods for dealing with ECC points"""
import ecdsa
from .compat import ecdsaAllCurves

def getCurveByName(curveName):
    """Return curve identified by curveName"""
    curves = {
        "secp256r1": ecdsa.NIST256p,
        "secp384r1": ecdsa.NIST384p,
        "secp521r1": ecdsa.NIST521p,
    }
    return curves.get(curveName)

def getPointByteSize(point):
    """Convert the point or curve bit size to bytes"""
    if isinstance(point, ecdsa.curves.Curve):
        return (point.baselen + 7) // 8
    elif isinstance(point, ecdsa.keys.VerifyingKey) or isinstance(point, ecdsa.keys.SigningKey):
        return (point.curve.baselen + 7) // 8
    else:
        raise ValueError("Unsupported point type")
