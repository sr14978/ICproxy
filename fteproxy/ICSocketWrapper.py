import innocuous_ciphertexts.emulator as emulator
import fteproxy.record_layer

import innocuous_ciphertexts.emulator.conf

from fteproxy import *

class _ICSocketWrapper(object):

    def __init__(self, _socket,
                 outgoing_regex=None, outgoing_fixed_slice=-1,
                 incoming_regex=None, incoming_fixed_slice=-1,
                 K1=None, K2=None):

        self._socket = _socket
        self._outgoing_regex = outgoing_regex
        self._outgoing_fixed_slice = outgoing_fixed_slice
        self._incoming_regex = incoming_regex
        self._incoming_fixed_slice = incoming_fixed_slice
        self._K1 = K1
        self._K2 = K2

        # self._negotiation_manager = NegotiationManager(K1, K2)
        # self._negotiationComplete = False

        self._isServer = (outgoing_regex is None and incoming_regex is None)
        self._isClient = (
            outgoing_regex is not None and incoming_regex is not None)
        self._incoming_buffer = ''
        self._preNegotiationBuffer_outgoing = ''
        self._preNegotiationBuffer_incoming = ''

        enc,dec = emulator.init(mode='proxy', just_URI=False, message_length=emulator.conf.frag_ciphertext_length, key_enc=K1, key_mac=K2)
        self._encoder = fteproxy.record_layer.Encoder(encoder=enc)
        self._decoder = fteproxy.record_layer.Decoder(decoder=dec)

    def fileno(self):
        return self._socket.fileno()

    def recv(self, bufsize):

        try:
            while True:
                data = self._socket.recv(bufsize)
                noData = (data == '')

                if noData and not self._incoming_buffer and not self._decoder._buffer:
                    return ''

                self._decoder.push(data)

                while True:
                    frag = self._decoder.pop()
                    if not frag:
                        break
                    self._incoming_buffer += frag

                if self._incoming_buffer:
                    break

            retval = self._incoming_buffer
            self._incoming_buffer = ''
        except ChannelNotReadyException:
            raise socket.timeout

        return retval

    def send(self, data):

        self._encoder.push(data)
        while True:
            to_send = self._encoder.pop()
            if not to_send:
                break
            self._socket.sendall(to_send)
        return len(data)

    def sendall(self, data):
        return self.send(data)

    def gettimeout(self):
        return self._socket.gettimeout()

    def settimeout(self, val):
        return self._socket.settimeout(val)

    def shutdown(self, flags):
        return self._socket.shutdown(flags)

    def close(self):
        return self._socket.close()

    def connect(self, addr):
        return self._socket.connect(addr)

    def accept(self):
        conn, addr = self._socket.accept()
        conn = _FTESocketWrapper(conn,
                                 self._outgoing_regex, self._outgoing_fixed_slice,
                                 self._incoming_regex, self._incoming_fixed_slice,
                                 self._K1, self._K2)

        return conn, addr

    def bind(self, addr):
        return self._socket.bind(addr)

    def listen(self, N):
        return self._socket.listen(N)
