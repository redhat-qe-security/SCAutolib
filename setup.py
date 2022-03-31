from setuptools import setup, find_packages
from os.path import curdir, realpath

description = "Python library for automation tests of smart cards using "\
    "virtualization."
with open(f"{realpath(curdir)}/requirements.txt", "r") as f:
    reqs = f.readlines()
with open(f"{realpath(curdir)}/SCAutolib/test/requirements.txt", "r") as f:
    test_reqs = f.readlines()

setup(
    name="SCAutolib",
    version="1.0.4",
    description=description,
    url="https://github.com/x00Pavel/SCAutolib",
    author="Pavel Yadlouski",
    author_email="pyadlous@redhat.com",
    classifiers=[
        'Programming Language :: Python :: 3',
        'Environment :: Console',
        'Framework :: Pytest',
        'Framework :: tox',
        'Intended Audience :: Developers',
        'Operating System :: Unix',
        'Topic :: Software Development :: Testing',
        'Topic :: Software Development :: Testing :: Acceptance',
    ],
    packages=find_packages(),
    python_requires='>=3',
    install_requires=reqs,
    tests_require=test_reqs,
    entry_points={
        "console_scripts": [
            "scauto=SCAutolib.src.cli_commands:cli",
            ]}
    )
