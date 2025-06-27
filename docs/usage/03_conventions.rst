Conventions we use in SCAutolib
===============================

This sections would introduce you conventions SCAutolib is using in sense of
development, documentation, different approaches, and etc.

1. Docstrings
----------------
Each model, class, method, property or function has to have docstring.
Description can be short, but has to be clear.
For methods and functions, docstring has to have specification of arguments
with data type, return value with data type and possible exceptions.

Examples:

.. code-block:: Python

    class CardManager:
        """
        Manages connections and basic operations with smart card readers and cards.

        This class provides high-level abstractions for common smart card interactions
        like connecting, disconnecting, and retrieving card attributes.
        """
        def connect(self, reader_index=0):
            """
            Establishes a connection to a smart card reader and the inserted card.

            :param reader_index: The zero-based index of the smart card reader to connect to.
                                Defaults to the first available reader (0).
            :type reader_index: int
            :raises SCAutolib.exceptions.PCSCError: If no reader is found or connection fails.
            :raises SCAutolib.exceptions.CardError: If no card is present or cannot be connected.
            """
            # ... implementation ...

.. code-block:: Python

    def put_certificate(slot_id, cert_data):
        """
        Stores a digital certificate onto a specific slot on the smart card.

        This function requires prior authentication with the card's management key.

        :param slot_id: The PIV slot ID where the certificate should be stored (e.g., 0x9A for authentication).
        :type slot_id: int
        :param cert_data: The certificate data in bytes (e.g., PEM format).
        :type cert_data: bytes
        :raises SCAutolib.exceptions.PivError: If the management key is not authenticated or slot is invalid.
        :raises SCAutolib.exceptions.CardError: For general card communication errors.
        :return: True if the certificate was successfully stored, False otherwise.
        :rtype: bool
        """
        # ... implementation ...

--------------------------

2. Unit test
--------------
All code should be covered by unit test unless there is specific reason
preventing it.
Especially, unit tests are required for functionality that can be tested
without changing the system state or do not require any special setup.
Always try to implement the test so it can be executed in GitHub Action
(aka in container).

--------------------------

3. Architecture
-----------------

* Functionality for manipulating with system is implemented in models.
* Business logic that glues functionality, that is provided by models, is
  implemented in controller.
* Before implementation, check existing classes for possible inheritance from
  them.
* In case of inheritance, if the new class do not support some functionality of
  parent class, not supported methods has to be overwritten and an appropriate
  exception has to be thrown.

--------------------------

4. Maintain Consistent Indentation (4 Spaces)
---------------------------------------------

To ensure maximum readability and maintainability across the SCAutolib
codebase, we strictly adhere to consistent formatting guidelines. All code must
use 4 spaces per indentation level, entirely avoiding tabs, which can lead to
visual inconsistencies across different development environments.

.. code-block:: Python

    def my_function():
        if condition:
                    # Mixed tabs and spaces or inconsistent spacing
            do_something()
        else:
              do_another_thing()

Good Practice:

.. code-block:: Python

        def my_function():
            if condition:
                # Consistent 4 spaces
                do_something()
            else:
                # Consistent 4 spaces
                do_another_thing()

--------------------------

5. Limit Line Length
--------------------

To keep the code easy to read and manage, especially during code reviews and on
various screen sizes, all lines of code should be limited to a maximum of 79
characters. Longer lines should be thoughtfully broken into multiple lines
using Python's implicit line continuation within parentheses, brackets, or
braces.

.. code-block:: Python

    # Very long line
    card_response = card_manager.send_apdu(0x00, 0xA4, 0x04, 0x00, b'D276000124010100000000000000000000000001', 0x00) # This APDU is super long for selecting an application on the card and it makes the line go way past the screen limit.

Good Practice:

.. code-block:: Python

    # Good Practice: Line breaking
    apdu_command = (
        b'\x00\xA4\x04\x00'  # CLA INS P1 P2
        b'\x0D'              # Lc (length of data field)
        b'D276000124010100000000000000000000000001' # Data
    )
    card_response = card_manager.send_apdu(
        0x00, 0xA4, 0x04, 0x00,
        apdu_command,
        0x00 # Le (expected length of response data)
    )
