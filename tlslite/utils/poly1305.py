"""Implementation of Poly1305 authenticator for RFC 7539"""
from .cryptomath import divceil

class Poly1305(object):
    """Poly1305 authenticator"""
    P = 1361129467683753853853498429727072845819

    @staticmethod
    def le_bytes_to_num(data):
        """Convert a number from little endian byte format"""
        return int.from_bytes(data, byteorder='little')

    @staticmethod
    def num_to_16_le_bytes(num):
        """Convert number to 16 bytes in little endian format"""
        return num.to_bytes(16, byteorder='little')

    def __init__(self, key):
        """Set the authenticator key"""
        if len(key) != 32:
            raise ValueError('Key must be 256 bit long')
        self.acc = 0
        self.r = self.le_bytes_to_num(key[0:16])
        self.r &= 21267647620597763993911028882763415551
        self.s = self.le_bytes_to_num(key[16:32])

    def create_tag(self, data):
        """Calculate authentication tag for data"""
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            if len(chunk) < 16:
                chunk += b'\x01' + b'\x00' * (15 - len(chunk))
            n = self.le_bytes_to_num(chunk)
            self.acc += n
            self.acc = (self.acc * self.r) % self.P
        self.acc += self.s
        return self.num_to_16_le_bytes(self.acc)
