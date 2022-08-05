Design of SCAutolib
=============================

This section describes design decisions that were made during
implementation with their explanations.

* **Library is designed for tests written in Beakerlib**
  Originally the library is designed to run in tests written in Beakerlib. From
  this perspective, the library provides setup and cleanup procedures for
  Beakerlib tests.
* **SCAutolib uses MVC pattern adopted for CLI and test usage.**

  MCV pattern is introduced to improve organization and structure of SCAutolib.
  Further design decisions respects this pattern giving developers some baseline
  for structuring of code. MVC is adopted into the context of SCAutolib in the
  following way:
  * Models are all basic classes in the library (CAs, Users, Card, etc.) that provides low-level atomic functionality
  * View is a CLI interface for manual interaction with the library
  * Controller is a heart of the library that handles logic behind both variants of the library usage: via View (aka CLI) and from imported code

  From this perspective, communication with models should be implemented only
  through the Controller.

* **All library-related directories and files (cards/users directory, library
  config files, backups) are stored in** ``/etc/SCAutolib``

  Reason for this is to simplify file management and cleanup phase after all
  tests are executed.
