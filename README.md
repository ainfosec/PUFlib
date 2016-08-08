PUFlib
======

Portable, modular library for manipulating and using physically-uncloneable functions (PUFs).

Motivation
-----------

Trusted computing primitives generally consist of a TPM or other chip-set extensions, making trusted
computing challenging on legacy or embedded platforms. PUFlib aims to alleviate those by providing
a seal() and unseal() API that relies on one or more PUFs, tying the sealed data to that *exact*
hardware. This project aims to both provide more PUF sources for greater hardware support.

Design
------

PUFlib is designed to be highly modular as PUFs are quite hardware-dependent. The core PUFlib aims
to provide a consistent API for usage and multi-PUF source support.

Documentation
-------------

API functions are documented in the headers under `include/`. To compile this documentation
into HTML for easy browsing, type `make docs` (requires Doxygen).

Implementing modules
--------------------

See `IMPLEMENTING.md` under `docs/` for information on how to implement new puflib modules.
