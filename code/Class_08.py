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
#
# PKCS#1 v2.2
# MGF1
# RSAES-OAEP-ENCRYPT
# RSAES-OAEP-DECRYPT


import hashlib
import binascii
import math
import typing
import random


default_crypto_random = random.SystemRandom()

if typing.TYPE_CHECKING:
    HashType = hashlib._Hash
else:
    HashType = typing.Any

def i2osp(x: int, x_len: int) -> bytes:
    '''Converts the integer x to its big-endian representation of length
       x_len.
    '''
    if x > 256**x_len:
        raise ValueError("Integer Too Large")
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = binascii.unhexlify(h)
    return b'\x00' * int(x_len-len(x)) + x

def os2ip(x: bytes) -> int:
    '''Converts the byte string x representing an integer reprented using the
       big-endian convient to an integer.
    '''
    h = binascii.hexlify(x)
    return int(h, 16)


def string_xor(a: bytes, b: bytes) -> bytes:
    '''Computes the XOR operator between two byte strings. If the strings are
       of different lengths, the result string is as long as the shorter.
    '''

    return bytes(x ^ y for (x, y) in zip(a, b))


def mgf1(mgf_seed: bytes, mask_len: int, hash_class: HashType = hashlib.sha256) -> bytes:
    '''
       Mask Generation Function v1 from the PKCS#1 v2.0 standard.

       mgs_seed - the seed, a byte string
       mask_len - the length of the mask to generate
       hash_class - the digest algorithm to use, default is SHA1

       Return value: a pseudo-random mask, as a byte string
       '''
    h_len = hash_class().digest_size
    if mask_len > ((2**32)*h_len):
        raise ValueError('Mask Too Long')
    
    T = b''
    for i in range(0, math.ceil(mask_len/h_len)):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    return T[:mask_len]


def oaep_encrypt(n: int, e: int, message: bytes, label: bytes = b'', 
        hash_class: HashType = hashlib.sha256, mgf=mgf1, seed=None, 
        rnd=default_crypto_random) -> bytes:
    '''Encrypt a byte message using a RSA public key and the OAEP wrapping
       algorithm,

       Parameters:
       public_key - an RSA public key
       message - a byte string
       label - a label a per-se PKCS#1 standard
       hash_class - a Python class for a message digest algorithme respecting
         the hashlib interface
       mgf1 - a mask generation function
       seed - a seed to use instead of generating it using a random generator
       rnd - a random generator class, respecting the random generator
       interface from the random module, if seed is None, it is used to
       generate it.

       Return value:
       the encrypted string of the same length as the public key
    '''

    hash = hash_class()
    h_len = hash.digest_size
    k = n.bit_length()//8
    max_message_length = k - 2 * h_len - 2
    # 1. check length
    if len(message) > max_message_length:
        raise ValueError('Message Too Long')
    # 2.EME-OAEP encoding
    hash.update(label)
    label_hash = hash.digest()
    ps = b'\0' * int(max_message_length - len(message))
    db = b''.join((label_hash, ps, b'\x01', message))
    
    if not seed:
        seed = i2osp(rnd.getrandbits(h_len*8), h_len)
        
    db_mask = mgf(seed, k - h_len - 1, hash_class=hash_class)
    masked_db = string_xor(db, db_mask)
    
    seed_mask = mgf(masked_db, h_len, hash_class=hash_class)
    masked_seed = string_xor(seed, seed_mask)
    
    em = b''.join((b'\x00', masked_seed, masked_db))
    # 3. RSA encryption
    m = os2ip(em)
    c = pow(m, e, n) # rsaep
    output = i2osp(c, k)
    return output

def oaep_decrypt(n: int, d: int, message: bytes, label: bytes=b'', hash_class=hashlib.sha256,
        mgf=mgf1) -> bytes:
    '''Decrypt a byte message using a RSA private key and the OAEP wrapping algorithm,

       Parameters:
       public_key - an RSA public key
       message - a byte string
       label - a label a per-se PKCS#1 standard
       hash_class - a Python class for a message digest algorithme respecting
         the hashlib interface
       mgf1 - a mask generation function

       Return value:
       the string before encryption (decrypted)
    '''
    hash = hash_class()
    h_len = hash.digest_size
    k = n.bit_length()//8
    # 1. check length
    if len(message) != k or k < 2 * h_len + 2:
        raise ValueError('Decryption Error')
        
    # 2. RSA decryption
    c = os2ip(message)
    m = pow(c, d, n) # rsadp
    em = i2osp(m, k)
    
    # 3. EME-OAEP decoding
    hash.update(label)
    label_hash = hash.digest()
    y, masked_seed, masked_db = em[0], em[1:h_len+1], em[1+h_len:]
    
    if y != b'\x00' and y != 0:
        raise ValueError('Decryption Error')
        
    seed_mask = mgf(masked_db, h_len)
    seed = string_xor(masked_seed, seed_mask)
    
    db_mask = mgf(seed, k - h_len - 1)
    db = string_xor(masked_db, db_mask)
    
    label_hash_prime, rest = db[:h_len], db[h_len:]
    i = rest.find(b'\x01')
    if i == -1:
        raise ValueError('Decryption Error')
        
    if rest[:i].strip(b'\x00') != b'':
        print(rest[:i].strip(b'\x00'))
        raise ValueError('Decryption Error')
        
    if label_hash_prime != label_hash:
        raise ValueError('Decryption Error')
        
    m = rest[i+1:]
    return m


if __name__ == '__main__':
    '''a = 0x1a2b3c4d5e6f
    r = i2osp(a, 32)
    print("i2osp test")
    assert len(r) == 32
    print("pass\n")
    
    b = os2ip(r)
    print("os2ip test")
    assert a == b
    print("pass\n")'''

    seed = (
        b"\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2" 
        b"\xf0\x6c\xb5\x8f"
    )
    db = (
        b"\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90"
        b"\xaf\xd8\x07\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd4\x36\xe9\x95\x69"
        b"\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49"
    )
    
    masked_db = (
        b"\xdc\xd8\x7d\x5c\x68\xf1\xee\xa8\xf5\x52\x67\xc3\x1b\x2e\x8b\xb4"
        b"\x25\x1f\x84\xd7\xe0\xb2\xc0\x46\x26\xf5\xaf\xf9\x3e\xdc\xfb\x25"
        b"\xc9\xc2\xb3\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb\x4c\xdc\xfe\x4f\xf4"
        b"\x77\x28\xb4\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a\xb4\x8d\x28\x69\xd5"
        b"\x02\x41\x21\x43\x58\x11\x59\x1b\xe3\x92\xf9\x82\xfb\x3e\x87\xd0"
        b"\x95\xae\xb4\x04\x48\xdb\x97\x2f\x3a\xc1\x4f\x7b\xc2\x75\x19\x52"
        b"\x81\xce\x32\xd2\xf1\xb7\x6d\x4d\x35\x3e\x2d"
    )

    db_mask = mgf1(seed, mask_len = len(db), hash_class = hashlib.sha1)
    expected_db_mask = (
        b"\x06\xe1\xde\xb2\x36\x9a\xa5\xa5\xc7\x07\xd8\x2c\x8e\x4e\x93\x24"
        b"\x8a\xc7\x83\xde\xe0\xb2\xc0\x46\x26\xf5\xaf\xf9\x3e\xdc\xfb\x25"
        b"\xc9\xc2\xb3\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb\x4c\xdc\xfe\x4f\xf4"
        b"\x77\x28\xb4\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a\xb4\x8d\x28\x69\xd5"
        b"\x02\x41\x21\x43\x58\x11\x59\x1b\xe3\x92\xf9\x82\xfb\x3e\x87\xd0"
        b"\x95\xae\xb4\x04\x48\xdb\x97\x2f\x3a\xc1\x4e\xaf\xf4\x9c\x8c\x3b"
        b"\x7c\xfc\x95\x1a\x51\xec\xd1\xdd\xe6\x12\x64"
    )

    print("mgf1 test1")
    assert db_mask == expected_db_mask
    print("pass\n")
    
    seed_mask = mgf1(masked_db, mask_len=len(seed), hash_class = hashlib.sha1)
    expected_seed_mask = (
        b"\x41\x87\x0b\x5a\xb0\x29\xe6\x57\xd9\x57\x50\xb5\x4c\x28\x3c\x08" 
        b"\x72\x5d\xbe\xa9"
    )
    
    print("mgf1 test2")
    assert seed_mask == expected_seed_mask
    print("pass\n")
    
    
    msg = '--- 我是芯片人阿伟 ---'
    #print("msg = ", msg)
    msg_b = msg.encode('utf-8')
    #print("msg_b = ", msg_b)
    
    # 公钥
    e = 0x10001
    n = 0x8394F8C70E1AB4F3F56643EEBEE27C363342E40F2534DD1CFFF7141D5C6AFB047BF814CE326B1FFE2FFEADDCBE19EA9D8AD44BC160B4BB2FED685C374EC192056FCFB10CDD1D1F60EF132E737ED1BC90E366AFCA294CDE3D7EC837146C9937A8BE893D2EC509A3CD8DEA1FE22ED75C5A22D0E5D2732DACEB731586F0DDAEC4D1CA6A7CDB8D720A975E2C6FB26B89BBF4BD7A8AC5EB91721D6038F47D2BABE9BA9F59332342CAE7F6FC479107BBC7F1FBB6403FE3F4C925A9EA00361CF2E263F0757E32CF4A5447010F4B2FE7694FD8FA641925734ADFFFEB0D30F86A3EE5D85FF6843E3BC499727763595BF180D55BFF6752138D1B738890EE85293E2DA5721F
    # 私钥
    p = 0xB57D58A4811D793E57915C551B8D656B59BE4F682DC4145ADC5770D6EA3FCF4A37D95E5EC46C587A29EC5A6610035169581E039AD6C173D2265D8574A8A251C236B1B0CCB4A900293D417CADD7155D1BAE60C753588476BF308D32FC9BCCE736ABB74D2AB9D2A96EE1DEE54662C91EB3268498BDFD63D063CCBFAC975E8D331714526BC355374A7F
    q = 0xB99A4C9D78D073A74907BE0D15A8C2A9941F2FA3C82CA6354C4362A5976E6EAF6824D2486FE471049B16036EAD291B2E872B9B65FC08D6FA9987BC47756A775AC838B7643A6523BF0E9AB981EFC019115EA54EA46A57B73F94A4B68D49DD0A64943205DD94851E88F49EFC825D7599A7952848D61901C861
    d = 0x65A262CA760580F1D3020BC4D4626269070D4AD4BBFB6A33252EF6B57B16130FB2A5BB844D835B31DE668C6AADD79CD5D54F07B8B576C403501044F25F7DBAC942451D4F7F57284E9A3BA9AC822F84C43131B6E4A32401A1645547DE19C7FB2AF709505DD8CA0A611295DDCCBA3B94D4F6817E93206E0E5B3ED8D6221B7A0AF33849A80AD0DC380C097F36C8035616AAF27C676B48B8A774D6532C14D8DC26FAF6EF548D056C47142C2DC75370BA3D86E7235CD338FB677C782FFB97FB4A3EE72A4B4595F0AEF14E468532046E49894820CCC61E9DCD8131AB54D6B6E35E1C24D967240ADD3D08D6BF8DFC4AED02677978FF5CA102FE33C54598BEE2260D9241
    
    
    m1 = oaep_encrypt(n, e, msg_b)
    #print("m1 = ", m1)
    print("RSA OAEP 加密测试")
    assert len(m1) == n.bit_length()//8
    print("pass\n")
    
    
    m2 = oaep_decrypt(n, d, m1)
    #print("m2 = ", m2)
    print("RSA OAEP 解密测试")
    assert m2 == msg_b
    assert msg == m2.decode("utf-8")
    print("pass\n")
    