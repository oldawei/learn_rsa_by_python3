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


import typing


# a % p
def mod_divide(a:int, p:int) -> typing.Tuple[int, int]: 
    #print("a = ", a)
    #print("p = ", p)
    if a < 0:
        c, r = mod_divide(-a, p)
        if r:
            return -c-1, p - r
        else:
            return -c, 0
    
    if a < p:
        #print("r = ", a)
        return 0, a
    
    a_len = a.bit_length()
    #print("a_len = ", a_len)
    
    p_len = p.bit_length()
    #print("p_len = ", p_len)
    
    d_len = a_len - p_len
    #print("d_len = ", d_len)
    
    if d_len == 0:
        #print("r = ", a - p)
        return 1, a - p
       
    c = 0
    for i in range(d_len, -1, -1):
        c = 2*c
        #print("i = ", i)
        a1 = a >> i
        #print("a1 = ", a1)
        if a1 < p:
            continue
        
        c = c + 1
        b1 = a - (a1 << i)
        #print("b1 = ", b1)
        
        a1 = a1 - p
        #print("_a1 = ", a1)
        
        a = (a1 << i) + b1
        #print("a = ", a)
        
    #print("r = ", a)
    return c, a
        

# a * b mod p
def mod_mult(a:int, b:int, p:int) -> int:
    _, a = mod_divide(a, p)
    _, b = mod_divide(b, p)
    r = 0
    
    for bit in range(b.bit_length()):
        if b & (1 << bit):
            _, r = mod_divide(r + a, p)
        _, a = mod_divide(a*2, p)
    
    return r
    
# a^b mod p
def mod_exp(a:int, b:int, p:int) -> int:
    _, a = mod_divide(a, p)
    r = 1
    
    for bit in range(b.bit_length(), -1, -1):
        r = mod_mult(r, r, p)
        if b & (1 << bit):
            r = mod_mult(r, a, p)
    
    return r

# ax + by = gcd(a, b)
# return x, y, gcd(a,b)
def ext_euclid(a:int, b:int):
    if b == 0:
        return 1, 0, a
    
    x, x0 = 1, 0
    y, y0 = 0, 1
    r, r0 = a, b
    while r0 != 0:
        #q = r // r0
        q, c = mod_divide(r, r0)
        r, r0 = r0, c
        #r, r0 = r0, r - q * r0
        x, x0 = x0, x - q * x0
        y, y0 = y0, y - q * y0
    
    #print(x, y, r)
    return x, y, r


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
    #r1 = r % p
    _, r1 = mod_divide(r, p)
    #print("r1", r1)

    x, y, g = ext_euclid(r, p)
    assert g == 1

    #q = -y % r
    _, q = mod_divide(-y, r)
    
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
    #r1 = r % p
    _, r1 = mod_divide(r, p)
    #print("r1", r1)

    # r2 = r*r mod p
    #r2 = r1 * r1 % p
    r2 = mod_mult(r1, r1, p)
    #print("r2", r2)

    x,y,g = ext_euclid(r, p)
    assert g == 1

    #q = -y % r
    _, q = mod_divide(-y, r)
    #print("q", q)

    ar = redc(a * r2, p, r, q)
    br = redc(b * r2, p, r, q)
    abr = redc(ar * br, p, r, q)
    return redc(abr, p, r, q)
    
def mg_mult_mod2(a:int, b:int, p:int, r:int, r2:int, q:int) -> int:
    """
    return a*b mod p

    a, b: integer in a*b mod p
    output = a*b mod p
    """

    ar = redc(a * r2, p, r, q)
    br = redc(b * r2, p, r, q)
    abr = redc(ar * br, p, r, q)
    return redc(abr, p, r, q)

# a^b mod p
def mg_exp_mod(a:int, b:int, p:int):
    _, a = mod_divide(a, p)

    a_p_len = max(a.bit_length(), b.bit_length(), p.bit_length())
    r_len = (a_p_len + 7) // 8 * 8
    #print("r_len", r_len)

    r = 2**r_len
    #print("r", r)

    # r1 = r mod p
    _, r1 = mod_divide(r, p)
    #print("r1", r1)

    # r2 = r*r mod p
    r2 = mod_mult(r1, r1, p)
    #print("r2", r2)

    x,y,g = ext_euclid(r, p)
    assert g == 1

    #q = -y % r
    _, q = mod_divide(-y, r)
    #print("q", q)


    rs = 1
    for bit in range(b.bit_length(), -1, -1):
        rs = mg_mult_mod2(rs, rs, p, r, r2, q)
        if b & (1 << bit):
            rs = mg_mult_mod2(rs, a, p, r, r2, q)
    
    return rs
    
    
import random
import time
    
if __name__ == '__main__':

    print("测试负数模运算")
    for i in range(100000):
        #print("")
        a = -random.randint(10000000000000, 99999999999999)
        #print("a = ", a)
        b = random.randint(1000000000000, 9999999999999)
        #print("b = ", b)
        
        q, r = mod_divide(a, b)
        assert q == a // b
        assert r == a % b
    print("pass\n")

    print("测试正数模运算")
    for i in range(100000):
        #print("")
        a = random.randint(10000000000000, 99999999999999)
        #print("a = ", a)
        b = random.randint(1000000000000, 9999999999999)
        #print("b = ", b)
        
        q, r = mod_divide(a, b)
        assert q == a // b
        assert r == a % b
    print("pass\n")
        
    print("测试模乘运算")
    for i in range(100):
        #print("")
        k = random.randint(1000, 5000)
        #print("k = ", k)
        
        a = random.randint(2**(k // 2), 2**(k // 2 + 1))
        #print("a = ", a)
        
        b = random.randint(2**(k // 3), 2**(k // 3 + 1))
        #print("b = ", b)
        
        p = random.randint(2**(k // 4), 2**(k // 4 + 1)) | 1
        assert mod_mult(a, b, p) == (a * b % p)
    print("pass\n")


    print("测试MG模乘运算")
    for i in range(100):
        #print("")
        k = random.randint(1000, 5000)
        #print("k = ", k)
        
        a = random.randint(2**(k // 2), 2**(k // 2 + 1))
        #print("a = ", a)
        
        b = random.randint(2**(k // 3), 2**(k // 3 + 1))
        #print("b = ", b)
        
        p = random.randint(2**(k // 4), 2**(k // 4 + 1)) | 1
        assert mg_mult_mod(a, b, p) == (a * b % p)
    print("pass\n")
    
    print("测试模幂运算")
    for i in range(10):
        #print("")
        k = random.randint(1000, 5000)
        print("k = ", k)
        
        a = random.randint(2**(k // 2), 2**(k // 2 + 1))
        #print("a = ", a)
        
        b = random.randint(2**(k // 3), 2**(k // 3 + 1))
        #print("b = ", b)
        
        p = random.randint(2**(k // 4), 2**(k // 4 + 1)) | 1
        
        t1 = time.time()
        rs1 = mod_exp(a, b, p)
        t2 = time.time()
        
        t3 = time.time()
        rs2 = pow(a, b, p)
        t4 = time.time()
        
        assert rs1 == rs2
        print("t1", t2-t1)
        print("t2", t4-t3)
        print("")
    print("pass\n")
    
    print("测试MG模幂运算")
    for i in range(10):
        #print("")
        k = random.randint(1000, 5000)
        print("k = ", k)
        
        a = random.randint(2**(k // 2), 2**(k // 2 + 1))
        #print("a = ", a)
        
        b = random.randint(2**(k // 3), 2**(k // 3 + 1))
        #print("b = ", b)
        
        p = random.randint(2**(k // 4), 2**(k // 4 + 1)) | 1
        
        t1 = time.time()
        rs1 = mg_exp_mod(a, b, p)
        t2 = time.time()
        
        t3 = time.time()
        rs2 = pow(a, b, p)
        t4 = time.time()
        
        assert rs1 == rs2
        print("t1", t2-t1)
        print("t2", t4-t3)
        print("")    
    print("pass\n")
