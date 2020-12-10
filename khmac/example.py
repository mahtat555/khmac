""" Examples
"""

from khmac import KHMAC


def main():
    """ Main function
    """
    # Example 1
    msg1 = "I am Mr. Yassin !"
    hmac1 = KHMAC("my secret key", msg1, "sha1")
    # Test the special method __repr__
    print(hmac1)
    # >>> KHMAC(fad1a8b3fe39cbf232d8ba11d85e6e1c5c252c98)
    # Test the hexdigest() method
    print(hmac1.hexdigest())
    # >>> fad1a8b3fe39cbf232d8ba11d85e6e1c5c252c98
    # Test the digest() method
    print(hmac1.digest())
    # >>> b'\xfa\xd1\xa8\xb3\xfe9\xcb\xf22\xd8\xba\x11\xd8^n\x1c\\%,\x98'

    # Example 2
    msg2 = b"I am Mr. "
    hmac2 = KHMAC("my secret key", msg2, "sha1")
    # Test the verify() method
    # Test the equality of $hmac1 and $hmac2
    if hmac1.verify(hmac2):
        print("hmac1 and hmac2 is equal")
    else:
        print("hmac1 and hmac2 isn't equal")
    # >>> hmac1 and hmac2 isn't equal

    # Example 3
    # Test the update() method
    hmac2.update("Yassin !")
    # Test the equality of $hmac1 and $hmac2
    if hmac1.verify(hmac2.hexdigest()):
        print("hmac1 and hmac2 is equal")
    else:
        print("hmac1 and hmac2 isn't equal")
    # >>> hmac1 and hmac2 is equal

    # Example 4
    # Test the hashname property
    print("hash1 function name : {}".format(hmac1.hashname))
    # >>> hash1 function name : sha1
    print("hash2 function name : {}".format(hmac2.hashname))
    # >>> hash1 function name : sha1

    # Example 1
    # Test the copy() method
    hmac3 = hmac1.copy()
    hmac3.update(" I am 25 years old.")
    # Test the equality of $hmac1 and $hmac3
    if hmac3.verify(hmac1.hexdigest()):
        print("hmac1 and hmac3 is equal")
    else:
        print("hmac1 and hmac3 isn't equal")


if __name__ == "__main__":
    main()
