# Smart Card Automation library (SCAutolib)
Test automation library for Smart Cards.

> ⚠️ This library is in development phase. There is nothing 100% stable.

SCAutolib is designed to run on RPM-based Linux distributions like RHEL 8, 
CentOS 8, Fedora 32 (or newer versions of mentioned distributions, backwards
compatibility is not supported). The primary goal of SCAutolib is to provide
functionality for automation of smart cards testing. This automation includes:

1. Environment setup via CLI commands
2. Interaction with created environment from the tests written in Python
3. Cleanup of the created environment

### TO BE DONE

Original design of the library is week and not flexible for new features and
needs. This why current design of the library would be changed. Until new
architecture is implemented, only critical bug fixes would be added to current
version.

## Installation

On Fedora, you need the following packages:

    # dnf install python3 git python3-pytest-env python3-coloredlogs python3-fabric python3-freeipa openssl

To run the tests locally:

    $ python -m pytest test/
