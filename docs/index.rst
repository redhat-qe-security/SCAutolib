.. SCAutolib documentation master file, created by
   sphinx-quickstart on Mon Apr  4 12:46:40 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

SCAutolib documentation
========================

.. toctree::
   :maxdepth: 2
   :hidden:
   :glob:

   usage/*
   API Reference <_autosummary/SCAutolib>

SCAutolib is a Python library designed for automating smart card testing,
developed by Red Hat QE Security. It aims to provide high-level functionality
for interacting with smart cards, abstracting complex low-level operations.
The project, currently in a development phase, utilizes an adapted MVC pattern
where "Models" handle core smart card logic (e.g., card operations,
card details), the "View" is its command-line interface (cli_commands.py), and
the "Controller" orchestrates interactions for both CLI and programmatic test
usage. This structure facilitates automated environment setup, interaction from
Python tests, and cleanup, making it a valuable tool for security compliance
and QA automation despite its ongoing architectural evolution.

Installation
************
.. note::
   SCAutolib is designed for RPM based Linux distribution like RHEL 8,
   CentOS 8, Fedora 30 (or later versions of mentioned distributions) because
   of specific RPM packages used for smart cards testing like SSSD and
   Authselect.

.. warning::

   SCAutolib is not working any more on RHEL 8 and CentOS 8 because of some
   needed packages that are not present on those distributions anymore.


.. code-block:: bash

   $ pip install SCAutolib

.. note::

   More detail can be found in :ref:`SCAutolib Setup` page.

Contributors
************

Special thanks to the following developers that contributed to the project:

* `Pavel Yadlouski <https://github.com/x00Pavel>`_

   Initial code implementation of the project.
   Code contributions.

* `Marek Havrila <https://github.com/mahavrila>`_

   Long term maintainer and creator of version 3 of the project.
   Code contributions.

* `Scott Poore  <https://github.com/spoore1>`_

   Extended CLI functionality to include graphical commands.
   Code contributions.

* `Jakub Jelen <https://github.com/Jakuje>`_

   Various code contributions.

* `George Pantelakis <https://github.com/GeorgePantelakis>`_

   Active maintainer.
   Various code contributions.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
