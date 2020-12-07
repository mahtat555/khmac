""" The main purpose of the `setup.py` script is to install your own
python package in a virtual environment.

"""

from os import path
from setuptools import setup, find_packages

import khmac

# Current directory
DIRNAME = path.dirname(__file__)


def readme(filename="README.md"):
    """This function is used to read the README file.

    Args:
        filename (str, optional): README file name. Defaults to "README.md".

    Returns:
        str: content of README file
    """
    with open(path.join(DIRNAME, filename)) as _file:
        return _file.read()


def requirements():
    """Returns the libraries (packages) required for the project to operate

    Returns:
        list: List of libraries required for project
    """
    with open(path.join(DIRNAME, "requirements.txt")) as _file:
        return _file.read().splitlines()


def main():
    """Main function
    """
    setup(
        # The name of library
        name=khmac.__name__,
        # The code version
        version=khmac.__version__,
        # Author info
        author=khmac.__author__,
        author_email=khmac.__email__,
        # An url that points to the official page of your lib
        url=khmac.__url__,
        # Licence used
        license=khmac.__license__,
        # A short description
        description="Keyed-Hash Message Authentication Code Python module",
        # A long description will be displayed to present the lib
        long_description=readme(),
        # List the packages to insert in the distribution
        packages=find_packages(),
        # A list of strings or a comma-separated string providing
        # descriptive meta-data
        keywords="khmac, hmac, mac, python",
        # Libraries (packages) required for the project to operate
        install_requires=requirements(),
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved",
            "Natural Language :: English",
            "Operating System :: OS Independent",
        ],
        python_requires='>=3.6',
    )


if __name__ == "__main__":
    main()
