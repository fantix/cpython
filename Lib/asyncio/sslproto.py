import collections
import warnings
try:
    import ssl
except ImportError:  # pragma: no cover
    ssl = None

from . import base_events
from . import constants
from . import protocols
from . import transports
from .log import logger


def _create_transport_context(server_side, server_hostname):
    if server_side:
        raise ValueError('Server side SSL needs a valid SSLContext')

    # Client side may pass ssl=True to use a default
    # context; in that case the sslcontext passed is None.
    # The default is secure for client connections.
    # Python 3.4+: use up-to-date strong settings.
    sslcontext = ssl.create_default_context()
    if not server_hostname:
        sslcontext.check_hostname = False
    return sslcontext


# States of an SSLProtocol
_UNWRAPPED = 0
_DO_HANDSHAKE = 1
_WRAPPED = 2
_SHUTDOWN = 3
_STATE_TRANSITIONS = (
    # 0 _UNWRAPPED
    (_DO_HANDSHAKE, _UNWRAPPED),

    # 1 _DO_HANDSHAKE
    (_WRAPPED, _UNWRAPPED),

    # 2 _WRAPPED
    (_SHUTDOWN, _UNWRAPPED),

    # 3 _SHUTDOWN
    (_UNWRAPPED,),
)
_RECORD_SIZE = 16384


class _SSLProtocolTransport(transports._FlowControlMixin,
                            transports.Transport):

    _sendfile_compatible = constants._SendfileMode.FALLBACK

    def __init__(self, loop, ssl_protocol):
        self._loop = loop
        # SSLProtocol instance
        self._ssl_protocol = ssl_protocol
        self._closed = False

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        return self._ssl_protocol._get_extra_info(name, default)

    def set_protocol(self, protocol):
        self._ssl_protocol._set_app_protocol(protocol)

    def get_protocol(self):
        return self._ssl_protocol._app_protocol

    def is_closing(self):
        return self._closed

    def close(self):
        """Close the transport.

        Buffered data will be flushed asynchronously.  No more data
        will be received.  After all buffered data is flushed, the
        protocol's connection_lost() method will (eventually) called
        with None as its argument.
        """
        self._closed = True
        self._ssl_protocol._start_shutdown()

    def __del__(self):
        if not self._closed:
            warnings.warn(f"unclosed transport {self!r}", ResourceWarning,
                          source=self)
            self.close()

    def is_reading(self):
        return not self._ssl_protocol._app_reading_paused

    def pause_reading(self):
        """Pause the receiving end.

        No data will be passed to the protocol's data_received()
        method until resume_reading() is called.
        """
        self._ssl_protocol._pause_reading()

    def resume_reading(self):
        """Resume the receiving end.

        Data received will once again be passed to the protocol's
        data_received() method.
        """
        self._ssl_protocol._resume_reading()

    def set_write_buffer_limits(self, high=None, low=None):
        """Set the high- and low-water limits for write flow control.

        These two values control when to call the protocol's
        pause_writing() and resume_writing() methods.  If specified,
        the low-water limit must be less than or equal to the
        high-water limit.  Neither value can be negative.

        The defaults are implementation-specific.  If only the
        high-water limit is given, the low-water limit defaults to an
        implementation-specific value less than or equal to the
        high-water limit.  Setting high to zero forces low to zero as
        well, and causes pause_writing() to be called whenever the
        buffer becomes non-empty.  Setting low to zero causes
        resume_writing() to be called only once the buffer is empty.
        Use of zero for either limit is generally sub-optimal as it
        reduces opportunities for doing I/O and computation
        concurrently.
        """
        self._ssl_protocol._set_write_buffer_limits(high, low)
        self._ssl_protocol._control_app_writing()

    def get_write_buffer_limits(self):
        return (self._ssl_protocol._outgoing_low_water,
                self._ssl_protocol._outgoing_high_water)

    def get_write_buffer_size(self):
        """Return the current size of the write buffer."""
        return self._ssl_protocol._get_write_buffer_size()

    @property
    def _protocol_paused(self):
        # Required for sendfile fallback pause_writing/resume_writing logic
        return self._ssl_protocol._app_writing_paused

    def write(self, data):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it
        to be sent out asynchronously.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"data: expecting a bytes-like instance, "
                            f"got {type(data).__name__}")
        if not data:
            return
        self._ssl_protocol._write_appdata((data,))

    def writelines(self, list_of_data):
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and
        calls write() on the result.
        """
        self._ssl_protocol._write_appdata(list_of_data)

    def can_write_eof(self):
        """Return True if this transport supports write_eof(), False if not."""
        return False

    def abort(self):
        """Close the transport immediately.

        Buffered data will be lost.  No more data will be received.
        The protocol's connection_lost() method will (eventually) be
        called with None as its argument.
        """
        self._ssl_protocol._abort()
        self._closed = True

    def _force_close(self, exc):
        # TODO: SSL over SSL
        pass


class SSLProtocol(protocols.BufferedProtocol):
    """SSL protocol.

    Implementation of SSL on top of a socket using incoming and outgoing
    buffers which are ssl.MemoryBIO objects.
    """

    def __init__(self, loop, app_protocol, sslcontext, waiter,
                 server_side=False, server_hostname=None,
                 call_connection_made=True,
                 ssl_handshake_timeout=None):
        if ssl is None:
            raise RuntimeError('stdlib ssl module not available')

        if ssl_handshake_timeout is None:
            ssl_handshake_timeout = constants.SSL_HANDSHAKE_TIMEOUT
        elif ssl_handshake_timeout <= 0:
            raise ValueError(
                f"ssl_handshake_timeout should be a positive number, "
                f"got {ssl_handshake_timeout}")

        if not sslcontext:
            sslcontext = _create_transport_context(
                server_side, server_hostname)

        self._server_side = server_side
        if server_hostname and not server_side:
            self._server_hostname = server_hostname
        else:
            self._server_hostname = None
        self._sslcontext = sslcontext
        # SSL-specific extra info. More info are set when the handshake
        # completes.
        self._extra = dict(sslcontext=sslcontext)

        # App data write buffering
        self._write_backlog = collections.deque()
        self._write_buffer_size = 0

        self._waiter = waiter
        self._loop = loop
        self._set_app_protocol(app_protocol)
        self._app_transport = _SSLProtocolTransport(self._loop, self)
        # transport, ex: SelectorSocketTransport
        self._transport = None
        self._call_connection_made = call_connection_made
        self._ssl_handshake_timeout = ssl_handshake_timeout
        # SSL and state machine
        self._sslobj = None
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl_buffer = bytearray(256 * 1024)
        self._state = _UNWRAPPED

        # Flow Control

        self._ssl_writing_paused = False

        self._app_reading_paused = False

        self._incoming_high_water = 0
        self._incoming_low_water = 0
        self._set_read_buffer_limits()

        self._app_writing_paused = False
        self._outgoing_high_water = 0
        self._outgoing_low_water = 0
        self._set_write_buffer_limits()

    def _set_app_protocol(self, app_protocol):
        self._app_protocol = app_protocol
        self._app_protocol_is_buffer = \
            isinstance(app_protocol, protocols.BufferedProtocol)

    def _wakeup_waiter(self, exc=None):
        if self._waiter is None:
            return
        if not self._waiter.cancelled():
            if exc is not None:
                self._waiter.set_exception(exc)
            else:
                self._waiter.set_result(None)
        self._waiter = None

    def connection_made(self, transport):
        """Called when the low-level connection is made.

        Start the SSL handshake.
        """
        self._transport = transport
        self._start_handshake()

    def connection_lost(self, exc):
        """Called when the low-level connection is lost or closed.

        The argument is an exception object or None (the latter
        meaning a regular EOF is received or the connection was
        aborted or closed).
        """
        self._set_state(_UNWRAPPED)
        self._loop.call_soon(self._app_protocol.connection_lost, exc)
        if self._app_transport is not None:
            self._app_transport._closed = True
        self._transport = None
        self._app_transport = None
        self._wakeup_waiter(exc)

    def get_buffer(self, n):
        if len(self._ssl_buffer) < n:
            self._ssl_buffer.extend(
                0 for _ in range(n - len(self._ssl_buffer)))
        return self._ssl_buffer

    def buffer_updated(self, nbytes):
        incoming = memoryview(self._ssl_buffer)[:nbytes]

        self._incoming.write(incoming)

        if self._state == _DO_HANDSHAKE:
            self._do_handshake()

        elif self._state == _WRAPPED:
            self._do_read()

        elif self._state == _SHUTDOWN:
            self._do_read()
            self._do_shutdown()

    def eof_received(self):
        """Called when the other end of the low-level stream
        is half-closed.

        If this returns a false value (including None), the transport
        will close itself.  If it returns a true value, closing the
        transport is up to the protocol.
        """
        try:
            if self._loop.get_debug():
                logger.debug("%r received EOF", self)

            self._wakeup_waiter(ConnectionResetError)

            if self._state != _DO_HANDSHAKE:
                keep_open = self._app_protocol.eof_received()
                if keep_open:
                    logger.warning('returning true from eof_received() '
                                   'has no effect when using ssl')
        finally:
            self._transport.close()

    def _get_extra_info(self, name, default=None):
        if name in self._extra:
            return self._extra[name]
        elif self._transport is not None:
            return self._transport.get_extra_info(name, default)
        else:
            return default

    def _fatal_error(self, exc, message='Fatal error on transport'):
        if isinstance(exc, base_events._FATAL_ERROR_IGNORE):
            if self._loop.get_debug():
                logger.debug("%r: %s", self, message, exc_info=True)
        else:
            self._loop.call_exception_handler({
                'message': message,
                'exception': exc,
                'transport': self._transport,
                'protocol': self,
            })
        if self._transport:
            self._transport._force_close(exc)

    def _set_state(self, new_state):
        if new_state not in _STATE_TRANSITIONS[self._state]:
            raise RuntimeError(
                'cannot switch state from {} to {}'.format(
                    self._state, new_state))

        self._state = new_state

    # Handshake flow

    def _start_handshake(self):
        if self._loop.get_debug():
            logger.debug("%r starts SSL handshake", self)
            self._handshake_start_time = self._loop.time()
        else:
            self._handshake_start_time = None

        self._set_state(_DO_HANDSHAKE)

        # start handshake timeout count down
        self._handshake_timeout_handle = \
            self._loop.call_later(self._ssl_handshake_timeout,
                                  self._check_handshake_timeout)

        try:
            self._sslobj = self._sslcontext.wrap_bio(
                self._incoming, self._outgoing,
                server_side=self._server_side,
                server_hostname=self._server_hostname)
        except Exception as ex:
            self._on_handshake_complete(ex)
        else:
            self._do_handshake()

    def _check_handshake_timeout(self):
        if self._state == _DO_HANDSHAKE:
            msg = (
                f"SSL handshake is taking longer than "
                f"{self._ssl_handshake_timeout} seconds: "
                f"aborting the connection"
            )
            self._fatal_error(ConnectionAbortedError(msg))

    def _do_handshake(self):
        try:
            self._sslobj.do_handshake()
        except ssl.SSLError as exc:
            if exc.errno in (ssl.SSL_ERROR_WANT_READ,
                             ssl.SSL_ERROR_WANT_WRITE,
                             ssl.SSL_ERROR_SYSCALL):
                if self._outgoing.pending:
                    self._transport.write(self._outgoing.read())
            else:
                self._on_handshake_complete(exc)
        else:
            self._on_handshake_complete(None)
            self._do_read()

    def _on_handshake_complete(self, handshake_exc):
        self._handshake_timeout_handle.cancel()

        sslobj = self._sslobj
        try:
            if handshake_exc is None:
                self._set_state(_WRAPPED)
            else:
                raise handshake_exc

            peercert = sslobj.getpeercert()
        except Exception as exc:
            self._set_state(_UNWRAPPED)
            if isinstance(exc, ssl.CertificateError):
                msg = 'SSL handshake failed on verifying the certificate'
            else:
                msg = 'SSL handshake failed'
            self._fatal_error(exc, msg)
            return

        if self._loop.get_debug():
            dt = self._loop.time() - self._handshake_start_time
            logger.debug("%r: SSL handshake took %.1f ms", self, dt * 1e3)

        # Add extra info that becomes available after handshake.
        self._extra.update(peercert=peercert,
                           cipher=sslobj.cipher(),
                           compression=sslobj.compression(),
                           ssl_object=sslobj,
                           )
        if self._call_connection_made:
            self._app_protocol.connection_made(self._app_transport)
        self._wakeup_waiter()

    # Shutdown flow

    def _start_shutdown(self):
        if self._state in (_SHUTDOWN, _UNWRAPPED):
            return
        if self._state == _DO_HANDSHAKE:
            self._abort()
        else:
            self._set_state(_SHUTDOWN)
            self._do_write()  # TODO: wait until all data is flushed
            self._do_shutdown()

    def _do_shutdown(self):
        try:
            self._sslobj.unwrap()
        except ssl.SSLError as exc:
            if exc.errno not in (ssl.SSL_ERROR_WANT_READ,
                                 ssl.SSL_ERROR_WANT_WRITE,
                                 ssl.SSL_ERROR_SYSCALL):
                raise
        else:
            self._set_state(_UNWRAPPED)
            self._loop.call_soon(self._transport.close)
        self._process_outgoing()

    def _abort(self):
        self._set_state(_UNWRAPPED)
        if self._transport is not None:
            self._transport.abort()

    # Outgoing flow

    def _write_appdata(self, list_of_data):
        for data in list_of_data:
            self._write_backlog.append(memoryview(data))
            self._write_buffer_size += len(data)

        try:
            if self._state == _WRAPPED:
                self._do_write()

        except Exception as ex:
            self._fatal_error(ex, 'Fatal error on SSL protocol')

    def _do_write(self):
        try:
            while self._write_backlog:
                view = self._write_backlog[0]
                count = self._sslobj.write(view)
                if count < len(view):
                    self._write_backlog[0] = view[count:]
                    self._write_buffer_size -= count
                else:
                    del self._write_backlog[0]
                    self._write_buffer_size -= len(view)
        except ssl.SSLError as exc:
            exc_errno = getattr(exc, 'errno', None)
            if exc_errno not in (ssl.SSL_ERROR_WANT_READ,
                                 ssl.SSL_ERROR_WANT_WRITE,
                                 ssl.SSL_ERROR_SYSCALL):
                raise
        self._process_outgoing()

    def _process_outgoing(self):
        if not self._ssl_writing_paused and self._outgoing.pending:
            self._transport.write(self._outgoing.read())
        self._control_app_writing()

    # Incoming flow

    def _do_read(self):
        try:
            if not self._app_reading_paused:
                if self._app_protocol_is_buffer:
                    self._do_read__buffered()
                else:
                    self._do_read__copied()
                self._do_write()
            self._control_ssl_reading()
        except Exception as ex:
            self._fatal_error(ex, 'Fatal error on SSL protocol')

    def _do_read__buffered(self):
        buf = memoryview(self._app_protocol.get_buffer(self._incoming.pending))
        wants = len(buf)
        offset = 0
        count = 1
        try:
            while offset < wants:
                count = self._sslobj.read(min(_RECORD_SIZE, wants - offset), buf[offset:])
                if not count:
                    break
                offset += count
            else:
                self._loop.call_soon(self._do_read)
        except ssl.SSLError as exc:
            if exc.errno not in (ssl.SSL_ERROR_WANT_READ,
                                 ssl.SSL_ERROR_WANT_WRITE,
                                 ssl.SSL_ERROR_SYSCALL):
                raise
        if offset:
            self._app_protocol.buffer_updated(offset)
        if not count:
            self._start_shutdown()

    def _do_read__copied(self):
        data = []
        chunk = 1
        try:
            while True:
                chunk = self._sslobj.read(_RECORD_SIZE)
                if not chunk:
                    break
                data.append(chunk)
        except ssl.SSLError as exc:
            if exc.errno not in (ssl.SSL_ERROR_WANT_READ,
                                 ssl.SSL_ERROR_WANT_WRITE,
                                 ssl.SSL_ERROR_SYSCALL):
                raise
        if data:
            self._app_protocol.data_received(b''.join(data))
        if not chunk:
            self._start_shutdown()

    # Flow control for writes from APP socket

    def _control_app_writing(self):
        size = self._get_write_buffer_size()
        if size >= self._outgoing_high_water and not self._app_writing_paused:
            self._app_writing_paused = True
            try:
                self._app_protocol.pause_writing()
            except Exception as exc:
                self._loop.call_exception_handler({
                    'message': 'protocol.pause_writing() failed',
                    'exception': exc,
                    'transport': self._app_transport,
                    'protocol': self,
                })
        elif size <= self._outgoing_low_water and self._app_writing_paused:
            self._app_writing_paused = False
            try:
                self._app_protocol.resume_writing()
            except Exception as exc:
                self._loop.call_exception_handler({
                    'message': 'protocol.resume_writing() failed',
                    'exception': exc,
                    'transport': self._app_transport,
                    'protocol': self,
                })

    def _get_write_buffer_size(self):
        return self._outgoing.pending + self._write_buffer_size

    def _set_write_buffer_limits(self, high=None, low=None):
        high, low = _add_water_defaults(high, low, 512)
        self._outgoing_high_water = high
        self._outgoing_low_water = low

    # Flow control for reads to APP socket

    def _pause_reading(self):
        self._app_reading_paused = True

    def _resume_reading(self):
        if self._app_reading_paused:
            self._app_reading_paused = False

            if self._state == _WRAPPED:
                self._do_read()
            elif self._state == _SHUTDOWN:
                self._do_read()
                self._do_shutdown()

    # Flow control for reads from SSL socket

    def _control_ssl_reading(self):
        size = self.get_read_buffer_size()
        if size >= self._incoming_high_water:
            self._transport.pause_reading()
        elif size <= self._incoming_low_water:
            self._transport.resume_reading()

    def _set_read_buffer_limits(self, high=None, low=None):
        high, low = _add_water_defaults(high, low, 256)
        self._incoming_high_water = high
        self._incoming_low_water = low

    def set_read_buffer_limits(self, high=None, low=None):
        self._set_read_buffer_limits(high, low)
        self._control_ssl_reading()

    def get_read_buffer_limits(self):
        return self._incoming_low_water, self._incoming_high_water

    def get_read_buffer_size(self):
        return self._incoming.pending

    # Flow control for writes to SSL socket

    def pause_writing(self):
        """Called when the low-level transport's buffer goes over
        the high-water mark.
        """
        assert not self._ssl_writing_paused
        self._ssl_writing_paused = True

    def resume_writing(self):
        """Called when the low-level transport's buffer drains below
        the low-water mark.
        """
        assert self._ssl_writing_paused
        self._ssl_writing_paused = False
        self._process_outgoing()


def _add_water_defaults(high, low, kb):
    if high is None:
        if low is None:
            high = kb * 1024
        else:
            high = 4 * low
    if low is None:
        low = high // 4

    if not high >= low >= 0:
        raise ValueError(
            f'high ({high!r}) must be >= low ({low!r}) must be >= 0')

    return high, low
