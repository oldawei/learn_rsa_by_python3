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
# RSASSA-PSS-SIGN
# RSASSA-PSS-VERIFY


import hashlib
import binascii
import math
import typing
import random

from Class_08 import *


def _and_byte(a: bytes, b: bytes) -> bytes:
    return bytes([a & b])


def _byte_eq(a: bytes, b: bytes) -> bytes:
    return bytes([a]) == b


def constant_time_cmp(a: bytes, b: bytes) -> bool:
    '''Compare two strings using constant time.'''
    result = True
    for x, y in zip(a,b):
        result &= (x == y)
    return result


def emsa_pss_encode(m: bytes, embits: int, hash_class: HashType=hashlib.sha256,
        mgf=mgf1, salt=None, s_len=None, rnd=default_crypto_random) -> bytes:
    '''Encode a message using the PKCS v2 PSS padding.

       m - the message to encode
       embits - the length of the padded message
       mgf - a masg generating function, default is mgf1 the mask generating
       function proposed in the PKCS#1 v2 standard.
       hash_class - the hash algorithm to use to compute the digest of the
       message, must conform to the hashlib class interface.
       salt - a fixed salt string to use, if None, a random string of length
       s_len is used instead, necessary for tests,
       s_len - the length of the salt string when using a random generator to
       create it, if None the length of the digest is used.
       rnd - the random generator used to compute the salt string

       Return value: the padded message
    '''
    m_hash = hash_class(m).digest()
    h_len = len(m_hash)
    if salt is not None:
        s_len = len(salt)
    else:
        if s_len is None:
            s_len = h_len
        salt = i2osp(rnd.getrandbits(s_len*8), s_len)
    em_len = math.ceil(embits / 8)
    if em_len < h_len + s_len + 2:
        raise ValueError('Encoding Error')
    m_prime = (b'\x00' * 8) + m_hash + salt
    h = hash_class(m_prime).digest()

    ps = b'\x00' * (em_len - s_len - h_len - 2)
    db = ps + b'\x01' + salt
    db_mask = mgf(h, em_len - h_len - 1)
    masked_db = string_xor(db, db_mask)

    octets, bits = (8 * em_len - embits) // 8, (8 * em_len - embits) % 8
    # replace first `octets' bytes
    masked_db = (b'\x00' * octets) + masked_db[octets:]
    new_byte = _and_byte(masked_db[octets], 255 >> bits)
    masked_db = masked_db[:octets] + new_byte + masked_db[octets+1:]
    return masked_db + h + b'\xbc'

def emsa_pss_verify(m: bytes, em: bytes, embits: int, hash_class:HashType=hashlib.sha256, 
        mgf=mgf1, s_len=None) -> bool:
    '''
       Verify that a message padded using the PKCS#1 v2 PSS algorithm matched a
       given message string.

       m - the message to match
       em - the padded message
       embits - the length in bits of the padded message
       hash_class - the hash algorithm used to compute the digest of the message
       mgf - the mask generation function
       s_len - the length of the salt string, if None the length of the digest is used.

       Return: True if the message matches, False otherwise.
    '''
    # 1. cannot verify, does not know the max input length of hash_class
    # 2. length check
    m_hash = hash_class(m).digest()
    h_len = len(m_hash)
    if s_len is None:
        s_len = h_len
    em_len = math.ceil(embits / 8)
    # 3. emlen check
    if em_len < h_len + s_len + 2:
        return False
    # 4. bc check
    if not _byte_eq(em[-1], b'\xbc'):
        return False
    # 5. get masked_db and h
    masked_db, h = em[:em_len-h_len-1], em[em_len-h_len-1:-1]
    # 6. zero check
    octets, bits = (8 * em_len - embits) // 8, (8*em_len-embits) % 8
    zero = masked_db[:octets] + _and_byte(masked_db[octets], ~(255 >> bits))
    for c in zero:
        if not _byte_eq(c, b'\x00'):
            return False
    # 7. get db_mask
    db_mask = mgf(h, em_len - h_len - 1)
    # 8. get db
    db = string_xor(masked_db, db_mask)
    # 9. set leftmost db to zero
    new_byte = _and_byte(db[octets], 255 >> bits)
    db = (b'\x00' * octets) + new_byte + db[octets+1:]
    # 10. ps check
    for c in db[:em_len-h_len-s_len-2]:
        if not _byte_eq(c, b'\x00'):
            return False
    # # \x01 check
    if not _byte_eq(db[em_len-h_len-s_len-2], b'\x01'):
        return False
    # 11. get salt
    salt = db[-s_len:]
    # 12. get m'
    m_prime = (b'\x00' * 8) + m_hash + salt
    # 13. get h'
    h_prime = hash_class(m_prime).digest()
    # 14. hash check
    return constant_time_cmp(h_prime, h)


def pss_sign(n: int, d: int, message: bytes, hash_class:HashType=hashlib.sha256,
        mgf=mgf1, rnd=default_crypto_random)-> bytes:
    '''Sign message using private_key and the PKCS#1 2.0 RSASSA-PSS
       algorithm.

       private_key - the private key to use
       message - the byte string to sign
       emsa_pss_encode - the encoding to use, default to EMSA-PSS encoding
       hash_class - the hash algorithme to use, default to SHA-1 from the
         Python hashlib package.
       mgf1 - the mask generating function to use, default to MGF1
       rnd - a random number generator to use for the PSS encoding,
       default to a Python SystemRandom instance.
    '''
    mod_bits = n.bit_length()
    embits = mod_bits - 1
    em = emsa_pss_encode(message, embits, hash_class=hash_class,
            mgf=mgf, rnd=rnd)
    m = os2ip(em)
    s = pow(m, d, n) # rsasp1
    return i2osp(s, mod_bits//8)

def pss_verify(n: int, e: int, message: bytes, signature: bytes, hash_class:HashType=hashlib.sha256, 
       mgf=mgf1) -> bool:
    '''Verify the signature of message signed using private_key and the
       PKCS#1 2.0 RSASSA-PSS algorithm.

       private_key - the private key to use
       message - the signed byte string
       signature - the byte string of the signature of the message
       emsa_pss_verify - the verify function for the used encoding,
         default to EMSA-PSS verification function
       hash_class - the hash algorithme to use, default to SHA-1 from the
         Python hashlib package.
       mgf1 - the mask generating function to use, default to MGF1
    '''
    mod_bits = n.bit_length()
    s = os2ip(signature)
    m = pow(s, e, n) # rsavp1
    embits = mod_bits - 1
    em_len = math.ceil(embits / 8)
    em = i2osp(m, em_len)
    return emsa_pss_verify(message, em, embits, hash_class=hash_class,
            mgf=mgf)

if __name__ == '__main__':
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
    
    
    sig = pss_sign(n, d, msg_b)
    #print("sig = ", sig)
    print("RSA PSS 签名测试")
    assert len(sig) == n.bit_length()//8
    print("pass\n")
    

    flag = pss_verify(n, e, msg_b, sig)
    #print("flag = ", flag)
    print("RSA PSS 验签测试")
    assert flag == True
    print("pass\n")
    