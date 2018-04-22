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
        encoder
    ):
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
            ciphertext = self._encoder.encrypt(plaintext)
            self._clear_buffer = self._clear_buffer[emulator.conf.frag_plaintext_length:]
            self._encrypted_buffer.append(ciphertext)

        self._length_dist_buffer = self._encoder.to_length_dist(self._encrypted_buffer)
        self._encrypted_buffer = []

        retval = "".join([self._encoder.encode(m) for m in self._length_dist_buffer])
        self._length_dist_buffer = []

        return retval


class Decoder:

    def __init__(
        self,
        decoder
    ):
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
        print "ppop---------------------------------------"
        while len(self._proxy_buffer) > 0:
            try:
                print "in================"
                msg, buffer = self._decoder.decode(self._proxy_buffer)
                self._length_dist_buffer.append(msg)
                self._proxy_buffer = buffer
            except Exception as e:
                fteproxy.warn("fteproxy.record_layer exception: "+str(e))
                break
            finally:
                if oneCell:
                    break

        self._encrypted_buffer, self._length_dist_buffer = self._decoder.from_length_dist(self._length_dist_buffer)

        retval = "".join([self._decoder.decrypt(c) for c in self._encrypted_buffer])
        self._encrypted_buffer = []

        return retval
