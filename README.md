fteproxy
========

* homepage: https://fteproxy.org
* source code: https://github.com/redjack/fteproxy
* publication: https://eprint.iacr.org/2012/494

Overview
--------

fteproxy is client-server proxy powered by Format-Transforming Encryption [1] that tunnels arbitrary TCP streams.
Regular expressions specified at runtime are used to format messages on the wire.
That is, given a regular epxression R, fteproxy can tunnel arbitrary TCP streams by transmitting messages in the language L(R).

[1] http://eprint.iacr.org/2012/494

Dependencies
--------

Dependencies for building from source:
* Standard build tools: gcc/g++/make/etc.
* git: http://git-scm.com/
* Python 2.7: http://python.org
* GMP: http://gmplib.org/
* gmpy: https://code.google.com/p/gmpy/
* PyCrypto: https://www.dlitz.net/software/pycrypto/
* Twisted: http://twistedmatrix.com/trac/
* boost (python, system, filesystem): http://www.boost.org/

Building
-----------

For platform-specific build instructions see: README.[linux|osx|windows]

However, once all dependencies are installed, it should be as simple
as
```
git clone https://github.com/redjack/fteproxy.git
cd fteproxy
make all
sudo make install
```
to build and install fteproxy.

Documentation
-------------

See: https://fteproxy.org/documentation
