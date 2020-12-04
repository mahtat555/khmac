""" The main purpose of the `setup.py` script is to install your own
python package in a virtual environment.

"""

from os import path


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
