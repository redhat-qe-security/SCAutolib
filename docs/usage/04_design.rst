Design of SCAutolib
===================

This section describes design decisions that were made during
implementation with their explanations.

* **Library is designed to be compatible with Red Hat testing environment**

  Tests in this environment are split to several phases: setup phase, test
  phase, and cleanup phase.
  From this perspective, the library provides setup and cleanup procedures.
  We have a setup, then multiple tests can be run with this setup, and finally
  we have a cleanup.

* **SCAutolib uses MVC pattern adopted for CLI and test usage.**

  SCAutolib is built with a flexible, layered architecture designed to make
  smart card automation intuitive and robust. At its heart, we've adopted an
  MVC (Model-View-Controller) pattern, adapting it to suit the unique needs of
  a Python library used for both direct command-line interaction and extensive
  test automation. This design approach aims to keep the codebase organized,
  reusable, and easy for new developers to understand and contribute to.

  While our architecture is continually evolving to introduce new features and
  enhance flexibility, the core MVC principles currently guide our design:

  * **Model**: The Smart Card's Brains

    Models are all basic classes in the library (CAs, Users, Card, etc.)
    that provides low-level atomic functionality

  * **View**: Your Command Center

    View is a Command-Line Interface (CLI) interface for manual interaction
    with the library

  * **Controller**: The Orchestrator

    Controller is a heart of the library that handles logic behind both
    variants of the library usage: via View (aka CLI) and from imported code

* **All library-related directories and files (cards/users directory, library
  config files, backups) are stored in** ``/etc/SCAutolib``

  Reason for this is to simplify file management and cleanup phase after all
  tests are executed.

--------------------------

SCAutolib in Depth
******************

This section describes the library in more detail.
In other words, this section contains our approach for adopting MVC pattern.

--------------------------

Models
#######

These are the foundational classes in the library (CAs, Users, Card, etc.)
that give you low-level, atomic control over the smart card setup and
operations. Think of them as the smart card's "brains" providing raw
functionality.

.. note::

    If some new moving part is added to the library (e.g. removinator),
    it should be added to the models.

Each model calls only its own methods and does not call **methods** of any
other models, except for model's **properties**.
In other words, models are not aware of other models, but only of their
properties.
This is made to clarify the implementation approach of the library: everything
that model requires for it's functionality is provided by the Controller.

For example, if you want to create a new LocalCA, you need to create a new CNF
file for this CA before calling the ``setup`` method on LocalCA object

.. code-block:: python

    ca_root_dir = "/etc/SCAutolib/ca"

    cnf_file = SCAutolib.models.file.OpensslCnf("/tmp/ca.cnf", "CA", ca_root_dir)
    cnf_file.create()
    cnf_file.save()

    local_ca = SCAutolib.models.ca.CA.LocalCA(root_dir=ca_root_dir, cnf=cnf_file)
    local_ca.setup()

This implementation would help to avoid situation with circular dependencies
and vague call of some method on unexpected place (model).

Some models have overwritten ``__dict__`` property so they can be serialized
to JSON format and stored in the file.
Overwriting ``__dict__`` is required because not every attribute of the model
is JSON serializable (e.g. pathlib.Path object).
After serialization, the model can be restored (loaded) via corresponding
``load`` method.

Example:

.. code-block:: python

    class BaseUser:
        @staticmethod
        def load(json_file, **kwargs):
            with json_file.open("r") as f:
                cnt = json.load(f)
            if cnt["local"]:
                user = User(local=cnt["local"],
                            username=cnt["username"],
                            password=cnt["password"], ...)
            else:
               # IPAUser is loaded similarly to LocalUser
               ...
            return user

    class User(BaseUser):
        ...
        @property
        def __dict__(self):
            dict_ = super().__dict__.copy()
            for k, v in dict_.items():
                if type(v) in (PosixPath, Path):
                    dict_[k] = str(v)

            if self._card:
                dict_["_card"] = str(self._card.dump_file)
            return dict_

Example of usage:

.. code-block:: python

    user = User(...)
    with user.dump_file("w") as f:
        json.dump(user.__dict__, f)
    loaded_user = BaseUser.load(user.dump_file)

``dump_file`` is an attribute of the model that defines path to the file where
the model is serialized.

--------------------------

Controller
###########

The Controller within SCAutolib serves as the essential "glue" connecting the
low-level atomic functionalities of the Models with the user's requests,
whether originating from the View (CLI) or programmatic automation. It
orchestrates the high-level logic, ensuring methods are called in the correct
sequence and managing the creation of necessary files and objects. While the
Controller's methods are designed to be invoked by the CLI or other system
setup scripts, they are intentionally not the primary interface for direct test
usage. This is to avoid unnecessary complexity for testing, as tests typically
require more granular control. Instead, for testing purposes, the Controller
facilitates the dumping of relevant Model states to JSON files upon method
completion. These JSON representations can then be loaded via test fixtures,
allowing test automation to directly interact with pre-configured Model
instances, craft specific smart card operations, execute them, and assert
against the outcomes with greater precision and efficiency. This flexible
Controller role enables both manual CLI control and robust, fine-grained
automated testing.

--------------------------

View
#####

The View component in SCAutolib serves as a direct interface for interacting
with the library's capabilities. Primarily, this is our
Command-Line Interface (CLI), encapsulated within ``cli_commands.py``. Its
core purpose is to provide an accessible API for users to leverage SCAutolib's
functionalities directly from their command line. This design is particularly
beneficial for those looking to integrate smart card operations into automation
scripts, like Bash, enabling quick execution and validation without needing to
write full Python programs. The CLI is intentionally designed to be lean,
focusing purely on capturing user input and presenting output. It avoids
embedding complex smart card logic, ensuring a clear separation of concerns
where the underlying "brains" of the smart card operations reside within the
Model layer, leaving the View to simply handle user interaction.
