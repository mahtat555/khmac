#!/usr/bin/python
# coding: utf-8

"""Keyed-Hash Message Authentication Code Python module.

This module is an implementation of the HMAC algorithm described by the
standard <<Key hash message authentication code (HMAC) (FIPS PUB 198).>>

"""

import hashlib
from _operator import _compare_digest as cmp

# ipad and opad were chosen in order to have an important Hamming distance
OPAD = bytes(i ^ 0x5c for i in range(256))
IPAD = bytes(i ^ 0x36 for i in range(256))

## Exclusive-Or function
# For Exclusive-Or `Key` with `ipad` and `Key` with `opad`
XOR = bytes.translate


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
        if hasattr(hashlib, hash_func):
            self.hash = hash
            hash_func = getattr(hashlib, hash_func)
        else:
            raise ValueError("unsupported hash type `{}`".format(hash))

        block_size = hash_func().block_size
        key_size = len(key)

        # step 1 -- determine key
        if key_size > block_size:
            # hash `key`, then append
            # zeros to create a block_size-bytes string `key`
            key = hash_func(key).ljust(block_size, b'\x00')

        elif key_size < block_size:
            # Append zeros to the end of `key`,
            # to create a block_size-bytes string `key`
            key = key.ljust(block_size, b'\x00')

        ## Calculate hmac
        # step 2 -- calculate hash(k + opad)
        self.block_1 = hash_func(XOR(key, OPAD))

        # step 3 -- calculate hash((k + ipad) || m)
        self.block_2 = hash_func(XOR(key, IPAD))
        self.block_2.update(msg)


    def __finalize(self):
        # step 4 -- calculate hash((k + opad) || hash((k + ipad) || m))
        hmac = self.block_1.copy()
        hmac.update(self.block_2.digest())
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
        self.block_2.update(msg)


    def verify(self, hmac: bytes) -> bool:
        """Checks if a `hmac` corresponds to the message using
        the secret key `key`.

        Parameters:
            hmac :bytes -- the digest value as a bytes object.

        Return :boolean -- return false if the `hmac` does not match,
            else return true.

        """
        return cmp(hmac, self.digest())
