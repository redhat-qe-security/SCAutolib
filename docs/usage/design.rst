Design of SCAutolib
=============================

This section describes design decisions that were made during
implementation with their explanations.

* **Library is designed to be compatible with Red Hat testing environment**

  Tests in this environment are split to several phases: setup phase, test
  phase, and cleanup phase.
  From this perspective, the library provides setup and cleanup procedures.

* **SCAutolib uses MVC pattern adopted for CLI and test usage.**

  MCV pattern is introduced to improve organization and structure of SCAutolib.
  Further design decisions respects this pattern giving developers some baseline for structuring of code.
  MVC is adopted into the context of SCAutolib in the following way:
   * Models are all basic classes in the library (CAs, Users, Card, etc.) that provides low-level atomic functionality
   * View is a CLI interface for manual interaction with the library
   * Controller is a heart of the library that handles logic behind both variants of the library usage: via View (aka CLI) and from imported code

* **All library-related directories and files (cards/users directory, library
  config files, backups) are stored in** ``/etc/SCAutolib``

  Reason for this is to simplify file management and cleanup phase after all
  tests are executed.


SCAutolib in Depth
******************************

This section describes the library in more detail.
In other words, this section contains our approach for adopting MVC pattern.

Models
#######
First of all, we have models. Models are classes that provide low-level atomic functionality.

.. note:: If some new moving part is added to the library (e.g. removinator), it should be added to the models.

Each model calls only its own methods and does not call **methods** of any other models, except for model's **properties**.
In other words, models are not aware of other models, but only of their properties.
This is made to clarify the implementation approach of the library: everything that model requires for it's functionality is provided by the Controller.
For example, if you want to create a new LocalCA, you need to create a new CNF file for this CA before calling the ``setup`` method on LocalCA object

.. code-block:: python

    ca_root_dir = "/etc/SCAutolib/ca"

    cnf_file = SCAutolib.models.file.OpensslCnf("/tmp/ca.cnf", "CA", ca_root_dir)
    cnf_file.create()
    cnf_file.save()

    local_ca = SCAutolib.models.ca.CA.LocalCA(root_dir=ca_root_dir, cnf=cnf_file)
    local_ca.setup()

This implementation would help to avoid situation with circular dependencies and vague call of some method on unexpected place (model).

Some models have overwritten ``__dict__`` property so they can be serialized to JSON format and stored in the file.
Overwriting ``__dict__`` is required because not every attribute of the model is JSON serializable (e.g. pathlib.Path object).
After serialization, the model can be restored (loaded) via corresponding ``load`` method.
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

``dump_file`` is an attribute of the model that defines path to the file where the model is serialized.

Controller
###########

Controller is a kind of glue between all models and the view.
While models are providing low-level atomic functionality, the controller is responsible for the high-level logic.
Controller calls methods in correct order along with creating all necessary files and objects.

Methods of the Controller are designed to be called from the View or from other code that would do setup of the system.
But it is not aimed to be called from the tests just because it is an overkill for them.
For tests purposes, each model, that is used in the tests, is dumped to the JSON file so it can be loaded in tests via fixtures.
Dumping of the models is done by the Controller at the end of method call.

View
#####

The View is a CLI interface for the library.
This is an API that you would use to access functionality of the library from the command line.
The reason to have this kind of interfaces is that the library is designed to be used programmatically in automation (Bash scripts).
