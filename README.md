# Keyed-Hash Message Authentication Code

This module is an implementation of the HMAC algorithm described by the standard [Key hash message authentication code (HMAC) (FIPS PUB 198).](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf).

**This implementation is written in python 3**

## install

```sh
$ git clone https://github.com/mahtat555/khmac.git
$ cd khmac/
$ python setup.py install
```

## usage

```python
>>> from khmac import KHMAC

>>> # Example 1
>>> hmac1 = KHMAC(
...     key="my secret key",
...     msg="I am Mr. Yassin !",
...     hash_func="sha1"
... )
>>> hmac1
KHMAC(fad1a8b3fe39cbf232d8ba11d85e6e1c5c252c98)
>>> hmac1.hexdigest()
'fad1a8b3fe39cbf232d8ba11d85e6e1c5c252c98'
>>> hmac1.digest()
b'\xfa\xd1\xa8\xb3\xfe9\xcb\xf22\xd8\xba\x11\xd8^n\x1c\\%,\x98'
>>>
>>> # Example 2
>>> hmac2 = KHMAC(
...     key="my secret key",
...     msg=b"I am Mr. "
... )
>>> if hmac1.verify(hmac2):
...     print("hmac1 and hmac2 is equal")
... else:
...     print("hmac1 and hmac2 is not equal")
hmac1 and hmac2 is not equal
>>>
>>> # Example 3
>>> hmac2.update("Yassin !")
>>> if hmac1.verify(hmac2):
...     print("hmac1 and hmac2 is equal")
... else:
...     print("hmac1 and hmac2 is not equal")
hmac1 and hmac2 is equal
>>>
>>> # Example 4
>>> hmac1.hashname
sha1
>>> hmac2.hashname
sha1
>>>
>>> # Example 1
>>> hmac3 = hmac1.copy()
>>> hmac3.update(" I am 25 years old.")
>>> if hmac3.verify(hmac1):
...     print("hmac1 and hmac3 is equal")
... else:
...     print("hmac1 and hmac3 is not equal")
hmac1 and hmac2 is not equal
```
