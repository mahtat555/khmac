#!/usr/bin/python
# coding: utf-8

"""Keyed-Hash Message Authentication Code Python module.

This module is an implementation of the HMAC algorithm described by the
standard <<Key hash message authentication code (HMAC) (FIPS PUB 198).>>

"""

import hashlib
from _operator import _compare_digest as cmp
from binascii import unhexlify, Error

# ipad and opad were chosen in order to have an important Hamming distance
OPAD = bytes(i ^ 0x5c for i in range(256))
IPAD = bytes(i ^ 0x36 for i in range(256))


def xor(key, pad):
    """Make the XOR between key and pad

    Args:
        key (bytes|bytearray|str): The secret key
        pad (bytes): Is equal to OPAD or IPAD

    Returns:
        (bytes|bytearray|str): XOR between key and pad
    """
    return key.translate(pad)


# KHMAC : keyed-hash message authentication code.
class KHMAC:
    """KHMAC(key :bytes, msg :bytes, hash="sha1").

    Allows the generation of a MAC (Message Authentication Code)
    from a cryptographic hash function.

    Methods :
        digest() -- Return the current digest value.
        hexdigest() -- Return the current digest as a string of
            hexadecimal digits.
        verify() -- Verify if the hmac corresponds to the message
            using the secret key.

    Parameters :
        key  :bytes -- The secret key. This must be kept secret.
        msg  :bytes -- The data on which the HMAC is calculated.
        hash :str -- An approved hash function, default `sha1`.

    Examples :
        >>> # Example 1
        >>> msg1 = b"I am Mr. Yassin !"
        >>> hmac1 = KHMAC(b"my secret key", msg1, "sha3_256")
        >>> h_digest = hmac1.digest()
        >>> msg2 = b"I am Mr. Yassin !"
        >>> hmac2 = KHMAC(b"my secret key", msg2, "sha3_256")
        >>> hmac2.verify(h_digest)
        True
        >>>
        ...
        >>> # Example 2
        >>> h1 = KHMAC(b"my secret key", b"Hello ")
        >>> h1.update(b"world !!")
        >>> h1_digest = h1.digest()
        >>> h2 =  KHMAC(b"my secret key", b"Hello world !!")
        >>> h2.verify(h1_digest)
        True

    """

    def __init__(self, key: bytes, msg: bytes, hash_func="sha1"):
        """Create a new `KHMAC` object.

        Parameters :
            key  :bytes -- Secret key shared between the originator
                  and the intended receiver(s).
            msg  :bytes -- He data you wish to pass into the context.
            hash :string -- The hash algorithm being used by this object.
                 Defaults to `sha1`.
                 Is in {'sha224', 'blake2b', 'sha512', 'md5', 'blake2s',
                 'sha3_224', 'sha384', 'sha3_384', 'sha3_256', 'sha3_512',
                 'sha256', 'sha1'}

        """
        # Test if the key is a bytes or bytearray or str
        if isinstance(key, str):
            key = key.encode()
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("This key is not a bytes or bytearray !")

        # Test if the message is a bytes or bytearray or str
        if isinstance(msg, str):
            msg = msg.encode()
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError("This message is not a bytes or bytearray !")

        # Test if the hash function is supported
        if callable(hash_func):
            hash_func = hash_func
        elif isinstance(hash_func, str) and hasattr(hashlib, hash_func):
            hash_func = getattr(hashlib, hash_func)
        else:
            raise ValueError("unsupported hash type `{}`".format(hash_func))

        block_size = hash_func().block_size

        if len(key) > block_size:
            key = hash_func(key).digest()

        key = key.ljust(block_size, b'\0')

        self.__block_1 = hash_func(xor(key, OPAD))
        self.__block_2 = hash_func(xor(key, IPAD))

        if msg:
            self.update(msg)

    @property
    def hashname(self):
        return self.__block_1.name

    def __finalize(self):
        """ Return a `KHMAC` object for the current state

        """
        hmac = self.__block_1.copy()
        hmac.update(self.__block_2.digest())
        return hmac

    def digest(self) -> bytes:
        """Return the digest value as a bytes object.

        """
        return self.__finalize().digest()

    def hexdigest(self) -> str:
        """Return the digest value as a string of hexadecimal digits.

        """
        return self.__finalize().hexdigest()

    def update(self, msg: bytes) -> None:
        """Update the hmac object. Repeated calls are equivalent to a single
        call with the concatenation of all the arguments:
            >>> h.update(a)
            >>> h.update(b)
            >>> # is equivalent to
            >>> h.update(a+b)

        """
        self.__block_2.update(msg)

    def verify(self, hmac) -> bool:
        """Check the equality of HMACs.

        Returns:
            boolean: return true if the HMACs are equal, else return false.
        """
        if isinstance(hmac, KHMAC) :
            hmac = hmac.digest()

        # Check if the hmac is hexadecimal
        try:
            hmac = unhexlify(hmac)
        except Error:
            pass

        return cmp(hmac, self.digest())
