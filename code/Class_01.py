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


def gcd(p: int, q: int) -> int:
    """Returns the greatest common divisor of p and q
    >>> gcd(48, 180)
    12
    """

    while q != 0:
        (p, q) = (q, p % q)
    return p
    

def lcm(p: int, q: int) -> int:
    """Returns the least common multiple of p and q
    >>> lcm(48, 180)
    720
    """

    return p * q // gcd(p, q)

if __name__=='__main__':
    assert gcd(5, 0) == 5
    assert gcd(0, 5) == 5

    assert gcd(5, 1) == 1
    assert gcd(1, 5) == 1

    assert gcd(4, 10) == 2
    assert gcd(5, 15) == 5
    
    assert lcm(4, 10) == 20
    assert lcm(5, 15) == 15

    assert gcd(0x12345678900001 * 0xFFFFFFF1, 0x98765432100001 * 0xFFFFFFF1) == 0xFFFFFFF1

    print("pass")
