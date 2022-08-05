SCAutolib Setup
========================

In order to be able to prepare the system for smart cards testing via the SCAutolib, following RPM packages are required:

* httpd
* opensc
* openssl
* sssd
* gnutls-utils
* gdm (optional, installed if ``--gdm`` switch is used)

If virtual smart card type is used for one of the users specified in configuration file, following additional packages are required:

* pcsc-lite-ccid
* pcsc-lite
* virt_cacard
* vpcd
* softhsm

Those packages can be installed using library by specifying ``--install-missing`` option to ``scauto prepare`` command.
However, you need to provide repository for these packages.
On RHEL/CentOS, most of the packages can be installed from BaseOS and AppStream repositories, but some packages requires additional repositories.
For example, softhsm package is available in EPEL repository, but it also can be installed from other source manually.

.. note:: RPM package virt_cacard is installed from known repository ``jjelen/vsmartcard``, so the repository for this one can be omitted because it would be added automatically.

During ``prepare`` command, Smart Card Support RPM group is installed.
