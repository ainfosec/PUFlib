PUFlib
======

Portable, modular library for manipulating and using physically-uncloneable functions (PUFs).

Motivation
-----------

Trusted computing primitives generally consist of a TPM or other chip-set extensions, making trusted
computing challenging on legacy or embedded platforms. PUFlib aims to alleviate those by providing
a seal() and unseal() API that relies on one or more PUFs, tying the sealed data to that *exact*
hardware. This project aims to both provide more PUF sources for greater hardware support as well as
abstract error correction to prevent temperature and hardware age induced errors.

Design
------

PUFlib is designed to be highly modular as PUFs are quite hardware-dependent. The core PUFlib aims
to provide a consistent API for usage as well as providing error-correction and multi-PUF source support.
Each module must define a module_info structure as well as the following three functions: is_hw_supported(),
 provision() and chal_resp().