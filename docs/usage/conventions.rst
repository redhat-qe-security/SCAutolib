Conventions we use in SCAutolib
===============================

This sections would introduce you conventions SCAutolib is using in sense of
development, documentation, different approaches, and etc.

1. Docstrings
----------------
Each model, class, method, property or function has to have docstring.
Description can be short, but has to be clear.
For methods and functions, docstring has to have specification of arguments with data type, return value with data type and possible exceptions.

2. Unit test
--------------
All code should be covered by unit test unless there is specific reason preventing it.
Especially, unit tests are required for functionality that can be tested without changing the system state or do not require any special setup.
Always try to implement the test so it can be executed in GitHub Action (aka in container).


3. Architecture
-----------------
Functionality for manipulating with system is implemented in models.
Business logic that glues functionality, that is provided by models, is implemented in controller.
Before implementation, check existing classes for possible inheritance from them.
In case of inheritance, if the new class do not support some functionality of parent class, not supported methods has to be overwritten and an appropriate exception has to be thrown.
