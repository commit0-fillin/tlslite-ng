"""Wrapper of TLS RecordLayer providing message-level abstraction"""
from .recordlayer import RecordLayer
from .constants import ContentType
from .messages import RecordHeader3, Message
from .utils.codec import Parser

class MessageSocket(RecordLayer):
    """TLS Record Layer socket that provides Message level abstraction

    Because the record layer has a hard size limit on sent messages, they need
    to be fragmented before sending. Similarly, a single record layer record
    can include multiple handshake protocol messages (very common with
    ServerHello, Certificate and ServerHelloDone), as such, the user of
    RecordLayer needs to fragment those records into multiple messages.
    Unfortunately, fragmentation of messages requires some degree of
    knowledge about the messages passed and as such is outside scope of pure
    record layer implementation.

    This class tries to provide a useful abstraction for handling Handshake
    protocol messages.

    :vartype recordSize: int
    :ivar recordSize: maximum size of records sent through socket. Messages
        bigger than this size will be fragmented to smaller chunks. Setting it
        to higher value than the default 2^14 will make the implementation
        non RFC compliant and likely not interoperable with other peers.

    :vartype defragmenter: Defragmenter
    :ivar defragmenter: defragmenter used for read records

    :vartype unfragmentedDataTypes: tuple
    :ivar unfragmentedDataTypes: data types which will be passed as-read,
        TLS application_data and heartbeat by default
    """

    def __init__(self, sock, defragmenter):
        """Apply TLS Record Layer abstraction to raw network socket.

        :type sock: socket.socket
        :param sock: network socket to wrap
        :type defragmenter: Defragmenter
        :param defragmenter: defragmenter to apply on the records read
        """
        super(MessageSocket, self).__init__(sock)
        self.defragmenter = defragmenter
        self.unfragmentedDataTypes = (ContentType.application_data, ContentType.heartbeat)
        self._lastRecordVersion = (0, 0)
        self._sendBuffer = bytearray(0)
        self._sendBufferType = None
        self.recordSize = 2 ** 14

    def recvMessage(self):
        """
        Read next message in queue

        will return a 0 or 1 if the read is blocking, a tuple of
        :py:class:`RecordHeader3` and :py:class:`Parser` in case a message was
        received.

        :rtype: generator
        """
        for result in self._recordLayer.recvRecord():
            if result in (0, 1):
                yield result
            else:
                header, parser = result
                yield (header, parser)

    def recvMessageBlocking(self):
        """Blocking variant of :py:meth:`recvMessage`."""
        for result in self.recvMessage():
            if result in (0, 1):
                pass
            else:
                return result

    def flush(self):
        """
        Empty the queue of messages to write

        Will fragment the messages and write them in as little records as
        possible.

        :rtype: generator
        """
        while self._sendBuffer:
            maximumSize = self.recordSize - 5
            if len(self._sendBuffer) > maximumSize:
                sendData = self._sendBuffer[:maximumSize]
                self._sendBuffer = self._sendBuffer[maximumSize:]
            else:
                sendData = self._sendBuffer
                self._sendBuffer = bytearray(0)

            message = Message(self._sendBufferType, sendData)
            for result in self._recordLayer.sendRecord(message):
                yield result

    def flushBlocking(self):
        """Blocking variant of :py:meth:`flush`."""
        for result in self.flush():
            pass

    def queueMessage(self, msg):
        """
        Queue message for sending

        If the message is of same type as messages in queue, the message is
        just added to queue.

        If the message is of different type as messages in queue, the queue is
        flushed and then the message is queued.

        :rtype: generator
        """
        if self._sendBuffer and msg.contentType != self._sendBufferType:
            for result in self.flush():
                yield result

        self._sendBuffer += msg.write()
        self._sendBufferType = msg.contentType

    def queueMessageBlocking(self, msg):
        """Blocking variant of :py:meth:`queueMessage`."""
        for result in self.queueMessage(msg):
            pass

    def sendMessage(self, msg):
        """
        Fragment and send a message.

        If a messages already of same type reside in queue, the message if
        first added to it and then the queue is flushed.

        If the message is of different type than the queue, the queue is
        flushed, the message is added to queue and the queue is flushed again.

        Use the sendRecord() message if you want to send a message outside
        the queue, or a message of zero size.

        :rtype: generator
        """
        for result in self.queueMessage(msg):
            yield result
        for result in self.flush():
            yield result

    def sendMessageBlocking(self, msg):
        """Blocking variant of :py:meth:`sendMessage`."""
        for result in self.sendMessage(msg):
            pass
