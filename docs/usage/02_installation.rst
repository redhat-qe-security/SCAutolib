===============
SCAutolib Setup
===============

SCAutolib is a Python library, so you'll need Python installed on your system.
We recommend using Python 3.6 or newer.

In order to install SCAutolib, the following RPM packages are required:

* ``gcc``
* ``krb5-devel``
* ``python3``
* ``python3-pip``
* ``python3-devel``

Then you can install SCAutolib via pip

.. code-block:: bash

    pip install --upgrade pip
    pip install SCAutolib

This command will download and install the library and its dependencies.
You might also need to install specific drivers for your smart card reader,
depending on your operating system and reader model. Refer to your smart card
reader's documentation for driver installation instructions.

After installing SCAutolib. In order to be able to prepare the system for smart
cards testing via the SCAutolib, following RPM packages are required:

* ``opensc``
* ``httpd``
* ``sssd``
* ``sssd-tools``
* ``gnutls-utils``
* ``openssl``
* ``nss-tools``
* ``gdm`` (optional, installed if ``--gdm`` switch is used)

If virtual smart card type is used for one of the users specified in
configuration file, the following additional RPM packages are required:

* ``pcsc-lite-ccid``
* ``pcsc-lite``
* ``virt_cacard``
* ``vpcd``
* ``softhsm``

If IPA user type is used in one of the users specified in configuration file,
the following additional RPM packages are required:

* ``e2fsprogs``
* ``freeipa-client`` (fedora) or ``ipa-client`` (CentOS, RHEL)

Those packages can be installed using library by specifying
``--install-missing`` option to ``scauto prepare`` command.
However, you need to provide repository for these packages.
On RHEL/CentOS, most of the packages can be installed from BaseOS and AppStream
repositories, but some packages requires additional repositories.
For example, softhsm package is available in EPEL repository, but it also can
be installed from other source manually.

.. note::

    RPM packages ``virt_cacard`` amd ``vpcd`` are installed from the copr
    repository ``jjelen/vsmartcard``, so the repository for this one can be
    omitted because it would be added automatically.

.. note::

    During ``prepare`` command, Smart Card Support RPM group is installed.
