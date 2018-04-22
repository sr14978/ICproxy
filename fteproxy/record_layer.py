#!/usr/bin/env python
# -*- coding: utf-8 -*-



import fte.encoder

import fteproxy.conf
from fte.encrypter import Encrypter
import innocuous_ciphertexts.emulator as emulator

MAX_CELL_SIZE = fteproxy.conf.getValue('runtime.fteproxy.record_layer.max_cell_size')


class Encoder:

    def __init__(
        self,
        encrypter,
        to_length_dist,
        encoder,
    ):
        self._encrypter = encrypter
        self._to_length_dist = to_length_dist
        self._encoder = encoder
        self._clear_buffer = ''
        self._encrypted_buffer = []
        self._length_dist_buffer = []

    def push(self, data):
        """Push data onto the FIFO buffer."""

        self._clear_buffer += data

    def pop(self):
        """Pop data off the FIFO buffer. We pop at most
        ``runtime.fteproxy.record_layer.max_cell_size``
        bytes. The returned value is encrypted and encoded
        with ``encoder`` specified in ``__init__``.
        """

        while len(self._clear_buffer) > 0:
            plaintext = self._clear_buffer[:emulator.conf.frag_plaintext_length]
            ciphertext = self._encrypter.encrypt(plaintext)
            self._clear_buffer = self._clear_buffer[emulator.conf.frag_plaintext_length:]
            _encrypted_buffer.append(ciphertext)

        self._length_dist_buffer = self._to_length_dist(self._encrypted_buffer)
        self._encrypted_buffer = []

        retval = "".join([self._encoder.encode(m) for m in self._length_dist_buffer])
        self._length_dist_buffer = []

        return retval


class Decoder:

    def __init__(
        self,
        decrypter,
        from_length_dist,
        decoder,
    ):
        self._decrypter = decrypter
        self._from_length_dist = from_length_dist
        self._decoder = decoder
        self._proxy_buffer = ''
        self._length_dist_buffer = []
        self._encrypted_buffer = []

    def push(self, data):
        """Push data onto the FIFO buffer."""

        self._proxy_buffer += data

    def pop(self, oneCell=False):
        """Pop data off the FIFO buffer.
        The returned value is decoded with ``_decoder`` then decrypted
        with ``_decrypter`` specified in ``__init__``.
        """

        while len(self._proxy_buffer) > 0:
            try:
                msg, buffer = self._decoder.decode(self._proxy_buffer)
                self._length_dist_buffer.append(msg)
                self._proxy_buffer = buffer
            except Exception as e:
                fteproxy.warn("fteproxy.record_layer exception: "+str(e))
                break
            finally:
                if oneCell:
                    break

        self._encrypted_buffer, self._length_dist_buffer = self._from_length_dist(self._length_dist_buffer)

        retval = "".join([self._decrypter.decrypt(c) for c in self._encrypted_buffer])
        self._encrypted_buffer = []

        return retval
