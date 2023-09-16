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


def ext_euclid(a: int, b: int) -> int:
    """Returns x, y, gcd(a,b) for linear equation: ax + by = gcd(a,b)
    """
    
    if b == 0:
        print(1, 0, a)
        return 1, 0, a
    
    x, x0 = 1, 0
    y, y0 = 0, 1
    r, r0 = a, b
    while r0 != 0:
        q = r // r0
        r, r0 = r0, r - q * r0
        x, x0 = x0, x - q * x0
        y, y0 = y0, y - q * y0
    
    #print(x, y, r)
    return x, y, r

def get_inv_mod(a: int, p: int):
    x, y, g = ext_euclid(a, p)
    assert g == 1

    return x % p


if __name__=='__main__':
    ext_euclid(5, 0)
    ext_euclid(0, 5)

    ext_euclid(5, 1)
    ext_euclid(1, 5)

    ext_euclid(4, 10)
    ext_euclid(5, 15)

    a = 0x12345678900001 * 0xFFFFFFF1
    b = 0x98765432100001 * 0xFFFFFFF1
    x, y, g = ext_euclid(a, b)
    assert g == 0xFFFFFFF1
    assert a * x + b * y == g

    a = 0xFFFFFFFF00000001
    p = 0xFFFFABCD00000001
    x, y, g = ext_euclid(a, p)
    assert g == 1

    inv_a = x % p
    assert a * inv_a % p == 1

    inv_p = y % a
    assert p * inv_p % a == 1

    inv_a = get_inv_mod(a, p)
    assert a * inv_a % p == 1

    print("pass")
