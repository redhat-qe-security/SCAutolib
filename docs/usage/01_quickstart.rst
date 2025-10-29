=================
Quick Start Guide
=================

This guide will help you quickly get started with **SCAutolib**, a powerful
Python library designed to simplify and automate the testing of **smart cards**
and **cryptographic operations** performed with them. Whether you're a seasoned
quality assurance engineer or new to smart card testing, SCAutolib provides a
robust framework to streamline your efforts.

--------------------------

What is SCAutolib?
==================

**SCAutolib** (Smart Card Automation Library) is a Python library that offers
a collection of utilities and functions to interact with smart cards and their
associated cryptographic functionalities. Its primary goal is to abstract away
the complexities of creating configurations manually, setting up the system for
testing and execute low-level smart card operations, allowing you to focus on
defining and executing your smart card test cases in an automated way. Think of
it as a toolkit that provides ready-to-use functions for common smart card
testing scenarios, such as:

* Set up virtual smart cards for testing.
* Set up test users and management of the users.
* Configuration of system for testing (Authselect, Card management, etc.).
* Smart card detection.
* Perform user login with card PIN in TTY.
* Perform user login with card PIN in su command.
* Perform user login with kerberos system and IPA server.
* Perform user login in GUI environment.
* Many more...

.. warning::
  The project is still in development. Some bugs or unwanted behavior
  is expected.

--------------------------

Why Use SCAutolib?
==================

* **Automation:** Automate repetitive smart card interactions and cryptographic
  tests, saving time and reducing manual errors.
* **Simplification:** Interact with complex configurations and smart
  card operations through simple, high-level Python functions.
* **Consistency:** Ensure consistent testing across different smart card types,
  readers, and testing environments.
* **Integration:** Easily integrate smart card testing into your existing CI/CD
  pipelines.
* **Extensibility:** Built with modularity in mind, allowing you to extend its
  functionality to support new smart card features or specific card types.

--------------------------

Basic Usage
===========

Let's dive into a simple example to illustrate how you can use SCAutolib. A
very common first step when testing smart cards is to setup a smart card for a
user and connect to the user with the pin of the card.

Here's a hypothetical example demonstrating how you might connect to a user
using a smart card. The user and card needs to exist beforehand:

..  code-block:: python

    import sys
    import logging
    import pexpect
    from SCAutolib.models.user import User
    from SCAutolib.models.authselect import Authselect
    from SCAutolib.models.card import Card

    log = logging.getLogger("Simple_test")

    log.info("Loading local user")
    local_user = User.load(username = "local_user")

    log.info("Loading token")
    local_user.card = Card.load(card_name = "my_token")

    log.info("Creating user shell")
    user_shell = pexpect.spawn("/usr/bin/sh -c 'su base-user'", encoding="utf-8")
    user_shell.logfile = sys.stdout

    log.info("Running test")
    with Authselect():
        with local_user.card(insert=True):
            cmd = f'su {local_user.username} -c "whoami"'
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {local_user.username}:")
            user_shell.sendline(local_user.pin)
            user_shell.expect_exact(local_user.username)


**Explanation:**

#.  **`local_user = load_user("local_user")`**: Finding the user and loading
    information about it.
#.  **`local_user.card = Card.load(card_name = "my_token")`**: Loading
    information about the card and add it to the user object.
#.  **`user_shell = pexpect.spawn(...)`**: Use pexpect to create an interactive
    local user terminal.
#.  **`with Authselect():`**: Context manager to setup Authselect, it accepts
    arguments.
#.  **`with local_user.card(insert=True):`**: insertion of the users card.

.. note::

    For creation of virtual user, card and setup of the system you can use
    scauto command that is provided by SCAutolib.

.. note::

    This is a very simple example. The library has many more capabilities

--------------------------

Next Steps
==========

Now that you have a basic understanding of SCAutolib and how to install it,
here are some suggestions for your next steps:

#. **Explore the SC-tests Repository:** Dive into the examples in the
   ``SC-tests`` repository to see practical applications of SCAutolib functions
   for various smart card operations.
#. **Refer to SCAutolib Documentation:** For detailed information on all
   available modules, classes, and functions within SCAutolib, refer to the
   official documentation.
#. **Experiment with Your Own Tests:** Start writing your own Python scripts
   using SCAutolib to automate your smart card operations.
#. **Contribute (Optional):** If you find bugs or have ideas for new features,
   consider contributing to the SCAutolib project on GitHub.

By following this guide, you're well on your way to leveraging SCAutolib for
more efficient and automated smart card and cryptographic testing.
