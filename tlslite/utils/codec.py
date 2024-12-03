"""Classes for reading/writing binary data (such as TLS records)."""
from __future__ import division
import sys
import struct
from struct import pack
from .compat import bytes_to_int

class DecodeError(SyntaxError):
    """Exception raised in case of decoding errors."""
    pass

class BadCertificateError(SyntaxError):
    """Exception raised in case of bad certificate."""
    pass

class Writer(object):
    """Serialisation helper for complex byte-based structures."""

    def __init__(self):
        """Initialise the serializer with no data."""
        self.bytes = bytearray(0)

    def addOne(self, val):
        """Add a single-byte wide element to buffer, see add()."""
        self.bytes.append(val & 0xFF)
    if sys.version_info < (2, 7):

        def addTwo(self, val):
            """Add a double-byte wide element to buffer, see add()."""
            self.bytes += struct.pack(">H", val)

        def addThree(self, val):
            """Add a three-byte wide element to buffer, see add()."""
            self.bytes += struct.pack(">I", val)[1:]

        def addFour(self, val):
            """Add a four-byte wide element to buffer, see add()."""
            self.bytes += struct.pack(">I", val)
    else:

        def addTwo(self, val):
            """Add a double-byte wide element to buffer, see add()."""
            self.bytes += val.to_bytes(2, byteorder='big')

        def addThree(self, val):
            """Add a three-byte wide element to buffer, see add()."""
            self.bytes += val.to_bytes(3, byteorder='big')

        def addFour(self, val):
            """Add a four-byte wide element to buffer, see add()."""
            self.bytes += val.to_bytes(4, byteorder='big')
    if sys.version_info >= (3, 0):

        def add(self, x, length):
            """
            Add a single positive integer value x, encode it in length bytes

            Encode positive integer x in big-endian format using length bytes,
            add to the internal buffer.

            :type x: int
            :param x: value to encode

            :type length: int
            :param length: number of bytes to use for encoding the value
            """
            self.bytes += x.to_bytes(length, byteorder='big')
    else:
        _addMethods = {1: addOne, 2: addTwo, 3: addThree, 4: addFour}

        def add(self, x, length):
            """
            Add a single positive integer value x, encode it in length bytes

            Encode positive iteger x in big-endian format using length bytes,
            add to the internal buffer.

            :type x: int
            :param x: value to encode

            :type length: int
            :param length: number of bytes to use for encoding the value
            """
            if length in self._addMethods:
                self._addMethods[length](self, x)
            else:
                for i in range(length-1, -1, -1):
                    self.bytes.append((x >> (8*i)) & 0xFF)

    def addFixSeq(self, seq, length):
        """
        Add a list of items, encode every item in length bytes

        Uses the unbounded iterable seq to produce items, each of
        which is then encoded to length bytes

        :type seq: iterable of int
        :param seq: list of positive integers to encode

        :type length: int
        :param length: number of bytes to which encode every element
        """
        for item in seq:
            self.add(item, length)

    if sys.version_info < (2, 7):

        def _addVarSeqTwo(self, seq):
            """Helper method for addVarSeq"""
            self.addTwo(len(seq))
            for item in seq:
                self.bytes += item

        def addVarSeq(self, seq, length, lengthLength):
            """
            Add a bounded list of same-sized values

            Create a list of specific length with all items being of the same
            size

            :type seq: list of int
            :param seq: list of positive integers to encode

            :type length: int
            :param length: amount of bytes in which to encode every item

            :type lengthLength: int
            :param lengthLength: amount of bytes in which to encode the overall
                length of the array
            """
            if lengthLength == 2:
                self._addVarSeqTwo(seq)
            else:
                self.add(len(seq), lengthLength)
                for item in seq:
                    self.add(item, length)
    else:

        def addVarSeq(self, seq, length, lengthLength):
            """
            Add a bounded list of same-sized values

            Create a list of specific length with all items being of the same
            size

            :type seq: list of int
            :param seq: list of positive integers to encode

            :type length: int
            :param length: amount of bytes in which to encode every item

            :type lengthLength: int
            :param lengthLength: amount of bytes in which to encode the overall
                length of the array
            """
            self.add(len(seq), lengthLength)
            for item in seq:
                self.add(item, length)

    def addVarTupleSeq(self, seq, length, lengthLength):
        """
        Add a variable length list of same-sized element tuples.

        Note that all tuples must have the same size.

        Inverse of Parser.getVarTupleList()

        :type seq: enumerable
        :param seq: list of tuples

        :type length: int
        :param length: length of single element in tuple

        :type lengthLength: int
        :param lengthLength: length in bytes of overall length field
        """
        self.add(len(seq), lengthLength)
        for tup in seq:
            for item in tup:
                self.add(item, length)

    def add_var_bytes(self, data, length_length):
        """
        Add a variable length array of bytes.

        Inverse of Parser.getVarBytes()

        :type data: bytes
        :param data: bytes to add to the buffer

        :param int length_length: size of the field to represent the length
            of the data string
        """
        self.add(len(data), length_length)
        self.bytes += data

class Parser(object):
    """
    Parser for TLV and LV byte-based encodings.

    Parser that can handle arbitrary byte-based encodings usually employed in
    Type-Length-Value or Length-Value binary encoding protocols like ASN.1
    or TLS

    Note: if the raw bytes don't match expected values (like trying to
    read a 4-byte integer from a 2-byte buffer), most methods will raise a
    DecodeError exception.

    TODO: don't use an exception used by language parser to indicate errors
    in application code.

    :vartype bytes: bytearray
    :ivar bytes: data to be interpreted (buffer)

    :vartype index: int
    :ivar index: current position in the buffer

    :vartype lengthCheck: int
    :ivar lengthCheck: size of struct being parsed

    :vartype indexCheck: int
    :ivar indexCheck: position at which the structure begins in buffer
    """

    def __init__(self, bytes):
        """
        Bind raw bytes with parser.

        :type bytes: bytearray
        :param bytes: bytes to be parsed/interpreted
        """
        self.bytes = bytes
        self.index = 0
        self.indexCheck = 0
        self.lengthCheck = 0

    def get(self, length):
        """
        Read a single big-endian integer value encoded in 'length' bytes.

        :type length: int
        :param length: number of bytes in which the value is encoded in

        :rtype: int
        """
        if self.index + length > len(self.bytes):
            raise DecodeError("Not enough data to read")
        result = bytes_to_int(self.bytes[self.index:self.index+length], 'big')
        self.index += length
        return result

    def getFixBytes(self, lengthBytes):
        """
        Read a string of bytes encoded in 'lengthBytes' bytes.

        :type lengthBytes: int
        :param lengthBytes: number of bytes to return

        :rtype: bytearray
        """
        if self.index + lengthBytes > len(self.bytes):
            raise DecodeError("Not enough data to read")
        result = self.bytes[self.index:self.index+lengthBytes]
        self.index += lengthBytes
        return result

    def skip_bytes(self, length):
        """Move the internal pointer ahead length bytes."""
        if self.index + length > len(self.bytes):
            raise DecodeError("Not enough data to skip")
        self.index += length

    def getVarBytes(self, lengthLength):
        """
        Read a variable length string with a fixed length.

        see Writer.add_var_bytes() for an inverse of this method

        :type lengthLength: int
        :param lengthLength: number of bytes in which the length of the string
            is encoded in

        :rtype: bytearray
        """
        length = self.get(lengthLength)
        return self.getFixBytes(length)

    def getFixList(self, length, lengthList):
        """
        Read a list of static length with same-sized ints.

        :type length: int
        :param length: size in bytes of a single element in list

        :type lengthList: int
        :param lengthList: number of elements in list

        :rtype: list of int
        """
        return [self.get(length) for _ in range(lengthList)]

    def getVarList(self, length, lengthLength):
        """
        Read a variable length list of same-sized integers.

        :type length: int
        :param length: size in bytes of a single element

        :type lengthLength: int
        :param lengthLength: size of the encoded length of the list

        :rtype: list of int
        """
        lengthList = self.get(lengthLength)
        return self.getFixList(length, lengthList)

    def getVarTupleList(self, elemLength, elemNum, lengthLength):
        """
        Read a variable length list of same sized tuples.

        :type elemLength: int
        :param elemLength: length in bytes of single tuple element

        :type elemNum: int
        :param elemNum: number of elements in tuple

        :type lengthLength: int
        :param lengthLength: length in bytes of the list length variable

        :rtype: list of tuple of int
        """
        length = self.get(lengthLength)
        return [tuple(self.getFixList(elemLength, elemNum)) for _ in range(length)]

    def startLengthCheck(self, lengthLength):
        """
        Read length of struct and start a length check for parsing.

        :type lengthLength: int
        :param lengthLength: number of bytes in which the length is encoded
        """
        self.lengthCheck = self.get(lengthLength)
        self.indexCheck = self.index

    def setLengthCheck(self, length):
        """
        Set length of struct and start a length check for parsing.

        :type length: int
        :param length: expected size of parsed struct in bytes
        """
        self.lengthCheck = length
        self.indexCheck = self.index

    def stopLengthCheck(self):
        """
        Stop struct parsing, verify that no under- or overflow occurred.

        In case the expected length was mismatched with actual length of
        processed data, raises an exception.
        """
        if self.index - self.indexCheck != self.lengthCheck:
            raise DecodeError("Length check failed")

    def atLengthCheck(self):
        """
        Check if there is data in structure left for parsing.

        Returns True if the whole structure was parsed, False if there is
        some data left.

        Will raise an exception if overflow occured (amount of data read was
        greater than expected size)
        """
        if self.index - self.indexCheck > self.lengthCheck:
            raise DecodeError("Length overflow")
        return self.index - self.indexCheck == self.lengthCheck

    def getRemainingLength(self):
        """Return amount of data remaining in struct being parsed."""
        return self.lengthCheck - (self.index - self.indexCheck)
