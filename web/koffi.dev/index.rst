Koffi
=====

Overview
--------

Koffi is a **fast and easy-to-use C FFI module for Node.js**, featuring:

* Low-overhead and fast performance (see :ref:`benchmarks<Benchmarks>`)
* Support for primitive and aggregate data types (structs and fixed-size arrays), both by reference (pointer) and by value
* Javascript functions can be used as C callbacks (since 1.2.0)
* Well-tested code base for :ref:`popular OS/architecture combinations<Supported platforms>`


Koffi requires a recent `Node.js <https://nodejs.org/>`_ version with N-API version 8 support, see :ref:`this page<Node.js>` for more information.

The source code is available here: https://github.com/Koromix/rygel/ (in the *src/koffi* subdirectory).

Table of contents
-----------------

.. toctree::
   :maxdepth: 2

   platforms
   start
   types
   functions
   callbacks
   memory
   benchmarks
   contribute
   changes

License
-------

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License** as published by the Free Software Foundation, either **version 3 of the License**, or (at your option) any later version.

Find more information here: https://www.gnu.org/licenses/
