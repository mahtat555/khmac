# Keyed-Hash Message Authentication Code

This module is an implementation of the HMAC algorithm described by the standard [Key hash message authentication code (HMAC) (FIPS PUB 198).](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf).

**This implementation is written in python 3**

## install

```sh
$ git clone https://github.com/mahtat555/khmac.git
```

## usage

```python
>>> from khmac.khmac import KHMAC
>>> # Example 1
>>> hmac1 = KHMAC(
       key = b"my secret key",
       msg = b"I am Mr. Yassin !",
       hash ="sha3_256"
    )
>>> h_digest = hmac1.digest()
>>> hmac2 = KHMAC(
       key = b"my secret key",
       msg = b"I am Mr. Yassin !",
       hash ="sha3_256"
    )
>>> hmac2.verify(h_digest)
True
>>> # Example 2
>>> h1 = KHMAC(b"my secret key", b"Hello ")
>>> h1.update(b"world !!")
>>> h1_digest = h1.digest()
>>> h2 =  KHMAC(
       key = b"my secret key",
       msg = b"Hello world !!"
    )
>>> h2.verify(h1_digest)
True
>>>
```
