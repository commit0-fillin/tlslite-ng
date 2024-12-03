"""
A state machine for using TLS Lite with asynchronous I/O.
"""

class AsyncStateMachine:
    """
    This is an abstract class that's used to integrate TLS Lite with
    asyncore and Twisted.

    This class signals wantsReadsEvent() and wantsWriteEvent().  When
    the underlying socket has become readable or writeable, the event
    should be passed to this class by calling inReadEvent() or
    inWriteEvent().  This class will then try to read or write through
    the socket, and will update its state appropriately.

    This class will forward higher-level events to its subclass.  For
    example, when a complete TLS record has been received,
    outReadEvent() will be called with the decrypted data.
    """

    def __init__(self):
        self.result = None
        self.handshaker = None
        self.closer = None
        self.reader = None
        self.writer = None
        self._clear()

    def wantsReadEvent(self):
        """If the state machine wants to read.

        If an operation is active, this returns whether or not the
        operation wants to read from the socket.  If an operation is
        not active, this returns None.

        :rtype: bool or None
        :returns: If the state machine wants to read.
        """
        if self.handshaker:
            return self.handshaker.wantsReadEvent()
        elif self.closer:
            return self.closer.wantsReadEvent()
        elif self.reader:
            return True
        elif self.writer:
            return False
        else:
            return None

    def wantsWriteEvent(self):
        """If the state machine wants to write.

        If an operation is active, this returns whether or not the
        operation wants to write to the socket.  If an operation is
        not active, this returns None.

        :rtype: bool or None
        :returns: If the state machine wants to write.
        """
        if self.handshaker:
            return self.handshaker.wantsWriteEvent()
        elif self.closer:
            return self.closer.wantsWriteEvent()
        elif self.reader:
            return False
        elif self.writer:
            return True
        else:
            return None

    def outConnectEvent(self):
        """Called when a handshake operation completes.

        May be overridden in subclass.
        """
        self.handshaker = None
        self.result = True

    def outCloseEvent(self):
        """Called when a close operation completes.

        May be overridden in subclass.
        """
        self.closer = None
        self.result = True

    def outReadEvent(self, readBuffer):
        """Called when a read operation completes.

        May be overridden in subclass."""
        self.reader = None
        self.result = readBuffer

    def outWriteEvent(self):
        """Called when a write operation completes.

        May be overridden in subclass."""
        self.writer = None
        self.result = True

    def inReadEvent(self):
        """Tell the state machine it can read from the socket."""
        if self.handshaker:
            try:
                self.handshaker.send(None)
            except StopIteration:
                self.outConnectEvent()
        elif self.closer:
            try:
                self.closer.send(None)
            except StopIteration:
                self.outCloseEvent()
        elif self.reader:
            try:
                readBuffer = self.reader.send(None)
                self.outReadEvent(readBuffer)
            except StopIteration:
                self.outReadEvent(None)

    def inWriteEvent(self):
        """Tell the state machine it can write to the socket."""
        if self.handshaker:
            try:
                self.handshaker.send(None)
            except StopIteration:
                self.outConnectEvent()
        elif self.closer:
            try:
                self.closer.send(None)
            except StopIteration:
                self.outCloseEvent()
        elif self.writer:
            try:
                self.writer.send(None)
                self.outWriteEvent()
            except StopIteration:
                self.outWriteEvent()

    def setHandshakeOp(self, handshaker):
        """Start a handshake operation.

        :param generator handshaker: A generator created by using one of the
            asynchronous handshake functions (i.e.
            :py:meth:`~.TLSConnection.handshakeServerAsync` , or
            handshakeClientxxx(..., async_=True).
        """
        self._clear()
        self.handshaker = handshaker
        self.result = None

    def setServerHandshakeOp(self, **args):
        """Start a handshake operation.

        The arguments passed to this function will be forwarded to
        :py:obj:`~tlslite.tlsconnection.TLSConnection.handshakeServerAsync`.
        """
        self._clear()
        self.handshaker = self.tlsConnection.handshakeServerAsync(**args)
        self.result = None

    def setCloseOp(self):
        """Start a close operation.
        """
        self._clear()
        self.closer = self.tlsConnection.closeAsync()
        self.result = None

    def setWriteOp(self, writeBuffer):
        """Start a write operation.

        :param str writeBuffer: The string to transmit.
        """
        self._clear()
        self.writer = self.tlsConnection.writeAsync(writeBuffer)
        self.result = None
