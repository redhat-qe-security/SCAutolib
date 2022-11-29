from setuptools import setup, find_packages
from pathlib import Path

description = "Python library for automation tests of smart cards using "\
    "virtualization."

here = Path(__file__).parent  # return directory of current file
readme = Path(here, "README.md")
requirements = Path(here, "requirements.txt")

with requirements.open() as f:
    reqs = f.readlines()

with readme.open() as f:
    long_description = f.read()

setup(
    name="SCAutolib",
    version="1.0.16",
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
    include_package_data=True,
    tests_require=["pytest", "pytest-env"],
    entry_points={
        "console_scripts": ["scauto=SCAutolib.cli_commands:cli"]}
)
