from setuptools import setup, find_packages
from os.path import curdir, realpath

description = "Python library for automation tests of smart cards using "\
    "virtualization."
here = realpath(curdir)
with open(f"{here}/requirements.txt", "r") as f:
    reqs = f.readlines()

with open(f"{here}/README.md", "r") as f:
    long_description = f.read()

setup(
    name="SCAutolib",
    version="v1.0.9",
    description=description,
    long_description=long_description,
    long_description_content_type='text/markdown',
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
    tests_require=["pytest"],
    entry_points={
        "console_scripts": ["scauto=SCAutolib.cli_commands:cli"]}
)
