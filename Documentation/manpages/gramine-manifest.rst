.. program:: gramine-manifest
.. _gramine-manifest:

============================================================
:program:`gramine-manifest` -- Gramine manifest preprocessor
============================================================

Synopsis
========

:command:`gramine-manifest` [*OPTION*]... [*SOURCE-FILE* [*OUTPUT-FILE*]]

Description
===========

:program:`gramine-manifest` is used to preprocess manifests for Gramine using
`Jinja markup <https://jinja.palletsprojects.com/>`__.

Command line arguments
======================

.. option:: --define <key>=<value>, -D <key>=<value>

   Have a |~| variable available in the template.

.. option:: --check

   After rendering manifest from template, perform validation against manifest
   schema to check for unknown manifest entries and/or missing mandatory
   options. See :doc:`gramine-manifest-check` for more details.

   The check is enabled by default. This option serves to re-enable the check
   after :option:`--no-check`.

.. option:: --no-check

   Disable schema validation, as described above in :option:`--check`.

.. option:: --chroot <path>

    When calculating cryptographic hashes of trusted files, measure files inside
    a |~| chroot instead of paths in root of the file system. Requires that all
    paths in manifest are absolute, and those will be interpreted as relative to
    the directory specified as the value of the option.

    Note you need to be very careful that the Gramine runtime binaries are
    exactly the same inside chroot as the ones used to execute
    :program:`gramine-manifest`.

Functions and constants available in templates
==============================================

.. default-domain:: py

.. data:: gramine.libos

   Path to :file:`libsysdb.so`.

.. function:: gramine.runtimedir(libc='glibc')

   The path to runtime directory with patched libc. Currently supported options
   are: ``'glibc'`` and ``'musl'``.

.. data:: python.stdlib

   ``stdlib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python.platstdlib

   ``platstdlib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python.purelib

   ``purelib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python.distlib

   On Debian systems, this is :file:`/usr/lib/python3/dist-packages`.

.. function:: python.get_path(...)

   `sysconfig.get_path
   <https://docs.python.org/3/library/sysconfig.html#sysconfig.get_path>`__

.. function:: python.get_paths(...)

   `sysconfig.get_paths
   <https://docs.python.org/3/library/sysconfig.html#sysconfig.get_paths>`__

.. data:: python.implementation

   `sys.implementation
   <https://docs.python.org/3/library/sys.html#sys.implementation>`__

.. data:: env.[ENVVAR]

   The content of ``$ENVVAR`` environment variable.

.. function:: ldd(\*executables)

   List of libraries which are linked from *executables*. Each library is
   provided at most once.

Example
=======

:file:`manifest.template`:

.. code-block:: jinja

   libos.entrypoint = "{{ entrypoint }}"
   loader.env.LD_LIBRARY_PATH = "/lib:{{ arch_libdir }}:/usr{{ arch_libdir }}"

   fs.mounts = [
     { path = "/lib", uri = "file:{{ gramine.runtimedir() }}" },
     { path = "/{{ entrypoint }}", uri = "file:{{ entrypoint }}" },
   ]

   sgx.trusted_files = [
     "file:{{ entrypoint }}",
     "file:{{ gramine.runtimedir() }}/",
   ]

:file:`Makefile`:

.. code-block:: make

   %.manifest: manifest.template
      gramine-manifest \
         -Dentrypoint=$(ENTRYPOINT) \
         -Darch_libdir=$(ARCH_LIBDIR) \
         $< $@
