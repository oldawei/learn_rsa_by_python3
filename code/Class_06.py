#  Copyright 2022 B站：芯片人阿伟
# https://space.bilibili.com/243180540
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


import os
import math
import typing
import struct
import random
#import Class_03


def bytes2int(raw_bytes: bytes) -> int:
    r"""Converts a list of bytes or an 8-bit string to an integer.

    When using unicode strings, encode it to some encoding like UTF8 first.
    """
    return int.from_bytes(raw_bytes, "big", signed=False)


def int2bytes(number: int, fill_size: int = 0) -> bytes:
    """
    Convert an unsigned integer to bytes (big-endian)::

    Does not preserve leading zeros if you don't specify a fill size.

    :param number:
        Integer value
    :param fill_size:
        If the optional fill size is given the length of the resulting
        byte string is expected to be the fill size and will be padded
        with prefix zero bytes to satisfy that length.
    :returns:
        Raw bytes (base-256 representation).
    :raises:
        ``OverflowError`` when fill_size is given and the number takes up more
        bytes than fit into the block. This requires the ``overflow``
        argument to this function to be set to ``False`` otherwise, no
        error will be raised.
    """

    if number < 0:
        raise ValueError("Number must be an unsigned integer: %d" % number)

    bytes_required = max(1, math.ceil(number.bit_length() / 8))

    if fill_size > 0:
        return number.to_bytes(fill_size, "big")

    return number.to_bytes(bytes_required, "big")
    
def read_random_bits(nbits: int) -> bytes:
    """Reads 'nbits' random bits.

    If nbits isn't a whole number of bytes, an extra byte will be appended with
    only the lower bits set.
    """

    nbytes, rbits = divmod(nbits, 8)

    # Get the random bytes
    randomdata = os.urandom(nbytes)

    # Add the remaining random bits
    if rbits > 0:
        randomvalue = ord(os.urandom(1))
        randomvalue >>= 8 - rbits
        randomdata = struct.pack("B", randomvalue) + randomdata

    return randomdata


def read_random_int(nbits: int) -> int:
    """Reads a random integer of approximately nbits bits."""

    randomdata = read_random_bits(nbits)
    value = bytes2int(randomdata)

    # Ensure that the number is large enough to just fill out the required
    # number of bits.
    value |= 1 << (nbits - 1)

    return value


def read_random_odd_int(nbits: int) -> int:
    """Reads a random odd integer of approximately nbits bits.
    """

    value = read_random_int(nbits)

    # Make sure it's odd
    return value | 1


def get_primality_testing_rounds(number: int) -> int:
    """Returns minimum number of rounds for Miller-Rabing primality testing,
    based on number bitsize.

    According to NIST FIPS 186-4, Appendix C, Table C.3, minimum number of
    rounds of M-R testing, using an error probability of 2 ** (-100), for
    different p, q bitsizes are:
      * p, q bitsize: 512; rounds: 7
      * p, q bitsize: 1024; rounds: 4
      * p, q bitsize: 1536; rounds: 3
    See: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    # Calculate number bitsize.
    bitsize = number.bit_length()
    # Set number of rounds.
    if bitsize >= 1536:
        return 3
    if bitsize >= 1024:
        return 4
    if bitsize >= 512:
        return 7
    # For smaller bitsizes, set arbitrary number of rounds.
    return 10


def miller_rabin_primality_testing(n: int, k: int) -> bool:
    """Calculates whether n is composite (which is always correct) or prime
    (which theoretically is incorrect with error probability 4**-k), by
    applying Miller-Rabin primality testing.

    For reference and implementation example, see:
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    :param n: Integer to be tested for primality.
    :type n: int
    :param k: Number of rounds (witnesses) of Miller-Rabin testing.
    :type k: int
    :return: False if the number is composite, True if it's probably prime.
    :rtype: bool
    """

    # prevent potential infinite loop when d = 0
    if n < 3:
        return False

    # Decompose (n - 1) to write it as (2 ** r) * d
    # While d is even, divide it by 2 and increase the exponent.
    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    # Test k witnesses.
    for _ in range(k):
        # Generate random integer a, where 2 <= a <= (n - 2)
        a = random.randint(2, n - 1)

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                # n is composite.
                return False
            if x == n - 1:
                # Exit inner loop and continue with next witness.
                break
        else:
            # If loop doesn't break, n is composite.
            return False

    return True


def is_prime(number: int) -> bool:
    """Returns True if the number is prime, and False otherwise.
    """

    # Check for small numbers.
    if number < 10:
        return number in {2, 3, 5, 7}

    # Check for even numbers.
    if not (number & 1):
        return False

    # Calculate minimum number of rounds.
    k = get_primality_testing_rounds(number)

    # Run primality testing with (minimum + 1) rounds.
    return miller_rabin_primality_testing(number, k + 1)
    

def getprime(nbits: int) -> int:
    """Returns a prime number that can be stored in 'nbits' bits.
    """

    assert nbits > 3  # the loop will hang on too small numbers

    while True:
        integer = read_random_odd_int(nbits)

        # Test for primeness
        if is_prime(integer):
            return integer

            # Retry if not prime


def find_p_q(nbits: int) -> typing.Tuple[int, int]:
    """Returns a tuple of two different primes of nbits bits each.

    The resulting p * q has exactly 2 * nbits bits, and the returned p and q
    will not be equal.

    :param nbits: the number of bits in each of p and q.
    :returns: (p, q), where p > q
    """

    total_bits = nbits * 2

    # Make sure that p and q aren't too close or the factoring programs can
    # factor n.
    shift = nbits // 16
    pbits = nbits + shift
    qbits = nbits - shift

    # Choose the two initial primes
    p = getprime(pbits)
    q = getprime(qbits)

    # Keep choosing other primes until they match our requirements.
    change_p = False
    while True:
        found_size = (p * q).bit_length()
        if (p != q) and (total_bits == found_size):
            break
        
        # Change p on one iteration and q on the other
        if change_p:
            p = getprime(pbits)
        else:
            q = getprime(qbits)

        change_p = not change_p

    # We want p > q as described on
    # http://www.di-mgt.com.au/rsa_alg.html#crt
    return max(p, q), min(p, q)


DEFAULT_EXPONENT = 65537
def gen_keys(nbits: int, exponent: int = DEFAULT_EXPONENT) -> typing.Tuple[int, int, int, int, int]:
    """Generate RSA keys of nbits bits. Returns (n, p, q, e, d).

    Note: this can take a long time, depending on the key size.

    :param nbits: the total number of bits in ``p`` and ``q``. Both ``p`` and
        ``q`` will use ``nbits/2`` bits.
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int
    """

    (p, q) = find_p_q(nbits // 2)
    n = p * q
    phi_n = (p-1)*(q-1)
    e = exponent
    #x, y, g = Class_03.ext_euclid(e, phi_n)
    #assert g == 1
    x = pow(e, -1, phi_n) # only worked for python3.9+
    
    d = x % phi_n
    assert e * d % phi_n == 1

    return n, p, q, e, d


def gen_prime_tbl(number: int):
    """Generate prime numbers in a list that less than param param. Returns the list.
    """
    
    prime_tbl = [2,3,5,7]
    for i in range(11, number):
        for p in prime_tbl:
            if i % p == 0:
                break;
        else:
            prime_tbl.append(i)

    return prime_tbl

def is_prime2(number: int, prime_tbl) -> bool:
    """test if a number is prime or not"""
    
    for p in prime_tbl:
        if number % p == 0:
            return False
    return True


if __name__ == '__main__':

    print("米勒拉宾素性测试")
    tbl = gen_prime_tbl(1<<16)
    for i in range(10000):
        p = getprime(32)
        #print(p)
        assert p.bit_length() == 32
        assert is_prime2(p, tbl) == True
    print("pass\n")
        
    
    print("生成大质数P、Q")
    p, q = find_p_q(1024)
    assert (p*q).bit_length() == 2048
    #print("p = 0x%X" % p)
    #print("q = 0x%X" % q)
    print("pass\n")
    
    print("生成RSA公钥、私钥")
    n, p, q, e, d = gen_keys(2048)
    print("n = 0x%X" % n)
    print("p = 0x%X" % p)
    print("q = 0x%X" % q)
    print("e = 0x%X" % e)
    print("d = 0x%X" % d)
    print("pass\n")

