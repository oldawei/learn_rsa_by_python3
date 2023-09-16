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

import Class_03


def redc(t:int, n:int, r:int, q:int) -> int:
    """
    return Montgomery reduction for integer t in mod n

    t: integer in t mod n
    n: mod n
    r: radix base, 2^k
    q: n * q % r = -1
    output = t*r^(-1) mod n
    """
    assert 0 <= t <= r*n-1
    #print("t", t)
    
    r_bit_len = r.bit_length() - 1
    #print("r_bit_len", r_bit_len)
    
    r_mask = r - 1
    #print("r_mask", r_mask)
    
    # m ← ((T mod R)N′) mod R
    m = ((t & r_mask) * q) & r_mask
    #print("m", m)
    
    # t ← (T + mN) / R  
    t = (t + m * n) >> r_bit_len
    #print("t", t)
    
    result = t if (t < n) else (t - n)
    #print("result", result)
    
    assert 0 <= result < n
    return result

def mg_mod(a:int, p:int) -> int:
    """
    return a mod p

    a: integer in a mod p
    output = a mod p
    """

    a_p_len = max(a.bit_length(), p.bit_length())
    r_len = (a_p_len + 7) // 8 * 8
    #print("r_len", r_len)

    r = 2**r_len
    #print("r", r)

    # r1 = r mod p
    r1 = r % p
    #print("r1", r1)

    x, y, g = Class_03.ext_euclid(r, p)
    assert g == 1

    q = -y % r
    #print("q", q)

    return redc(a * r1, p, r, q)

def mg_mult_mod(a:int, b:int, p:int) -> int:
    """
    return a*b mod p

    a, b: integer in a*b mod p
    output = a*b mod p
    """

    a_p_len = max(a.bit_length(), b.bit_length(), p.bit_length())
    r_len = (a_p_len + 7) // 8 * 8
    #print("r_len", r_len)

    r = 2**r_len
    #print("r", r)

    # r1 = r mod p
    r1 = r % p
    #print("r1", r1)

    # r2 = r*r mod p
    r2 = r1 * r1 % p
    #print("r2", r2)

    x,y,g = Class_03.ext_euclid(r, p)
    assert g == 1

    q = -y % r
    #print("q", q)

    ar = redc(a * r2, p, r, q)
    br = redc(b * r2, p, r, q)
    abr = redc(ar * br, p, r, q)
    return redc(abr, p, r, q)

if __name__=='__main__':
    assert mg_mod(50, 17) == (50 % 17)
    assert mg_mod(50, 33) == (50 % 33)
    
    a = 2**1200 + 1
    p = 2**1024 + 1
    assert mg_mod(a, p) == (a % p)

    b = 2**1100 + 1
    assert mg_mult_mod(a, b, p) == ((a * b) % p)

    print("pass")
