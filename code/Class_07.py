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
import typing
import random
import base64
import hashlib
import Class_06


if typing.TYPE_CHECKING:
    HashType = hashlib._Hash
else:
    HashType = typing.Any


# ASN.1 codes that describe the hash algorithm used.
HASH_ASN1 = {
    "MD5": b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    "SHA-1": b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    "SHA-224": b"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c",
    "SHA-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    "SHA-384": b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    "SHA-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
    "SHA3-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08\x05\x00\x04\x20",
    "SHA3-384": b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09\x05\x00\x04\x30",
    "SHA3-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a\x05\x00\x04\x40",
}

HASH_METHODS: typing.Dict[str, typing.Callable[[], HashType]] = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-384": hashlib.sha3_384,
    "SHA3-512": hashlib.sha3_512,
}


# EME-PKCS1-v1_5
# len(PS) >= 8
# PS is nonzero random data
def _pad_for_encryption(message: bytes, target_length: int) -> bytes:
    r"""Pads the message for encryption, returning the padded message.

    :return: 00 02 PS 00 M
    """

    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        raise OverflowError(
            "%i bytes needed for message, but there is only"
            " space for %i" % (msglength, max_msglength)
        )

    # Get random padding
    padding = b""
    padding_length = target_length - msglength - 3

    # We remove 0-bytes, so we'll end up with less padding than we've asked for,
    # so keep adding data until we're at the correct length.
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)

        # Always read at least 8 bytes more than we need, and trim off the rest
        # after removing the 0-bytes. This increases the chance of getting
        # enough bytes, especially when needed_bytes is small
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b"\x00", b"")
        padding = padding + new_padding[:needed_bytes]

    assert len(padding) == padding_length

    return b"".join([b"\x00\x02", padding, b"\x00", message])


# EMSA-PKCS1-v1_5
# len(PS) >= 8
# PS is 0xFF
def _pad_for_signing(message: bytes, target_length: int) -> bytes:
    r"""Pads the message for signing, returning the padded message.

    The padding is always a repetition of FF bytes.

    :return: 00 01 PS 00 M
    """

    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        raise OverflowError(
            "%i bytes needed for message, but there is only"
            " space for %i" % (msglength, max_msglength)
        )

    padding_length = target_length - msglength - 3

    return b"".join([b"\x00\x01", padding_length * b"\xff", b"\x00", message])
    

def _find_method_hash(clearsig: bytes) -> str:
    """Finds the hash method.

    :param clearsig: full padded ASN1 and hash.
    :return: the used hash method.
    :raise VerificationFailed: when the hash method cannot be found
    """

    for (hashname, asn1code) in HASH_ASN1.items():
        if asn1code in clearsig:
            return hashname

    raise ValueError("Verification failed")


def compute_hash(message: bytes, method_name: str) -> bytes:
    """Returns the message digest.

    :param message: the signed message. Can be an 8-bit string.
    :param method_name: the hash method, must be a key of
        :py:const:`HASH_METHODS`.
    """

    if method_name not in HASH_METHODS:
        raise ValueError("Invalid hash method: %s" % method_name)

    method = HASH_METHODS[method_name]
    hasher = method()

    hasher.update(message)

    return hasher.digest()


def rsa_encryption(msg:str, n: int, e:int) -> str:
    klen = n.bit_length() // 8
    #print("klen = ", klen)
    message = msg.encode('utf-8')
    
    em = _pad_for_encryption(message, klen)
    m = Class_06.bytes2int(em)
    c = pow(m, e, n)
    #print("clen = ", c.bit_length())
    
    return base64.b64encode(Class_06.int2bytes(c))
    

def rsa_decryption(enc_msg:str, n: int, d:int) -> str:
    klen = n.bit_length() // 8
    #print("klen = ", klen)
    
    c = Class_06.bytes2int(base64.b64decode(enc_msg))
    m = pow(c, d, n)
    em = Class_06.int2bytes(m, klen)
    #print("em = ", em)
    
    if em[:2] != b"\x00\x02":
        return ""
        
    sep_idx = em.find(b"\x00", 2)
    if sep_idx < 10:
        return ""
    
    return em[sep_idx + 1 :].decode('utf-8')


def rsa_sign(message:str, hash_method: str, n: int, d:int) -> str:
    # Get the ASN1 code for this hash method
    if hash_method not in HASH_ASN1:
        raise ValueError("Invalid hash method: %s" % hash_method)
    asn1code = HASH_ASN1[hash_method]
    
    klen = n.bit_length() // 8
    #print("klen = ", klen)
    
    # Encrypt the hash with the private key
    h = compute_hash(message.encode('utf-8'), hash_method)
    t = asn1code + h
    
    em = _pad_for_signing(t, klen)
    m = Class_06.bytes2int(em)
    
    c = pow(m, d, n)
    #print("clen = ", c.bit_length())
    
    return base64.b64encode(Class_06.int2bytes(c))
    
def rsa_verify(message:str, signature:str, n: int, e:int) -> bool:
    klen = n.bit_length() // 8
    #print("klen = ", klen)
    
    signature = base64.b64decode(signature)
    c = Class_06.bytes2int(signature)
    m = pow(c, e, n)
    em = Class_06.int2bytes(m, klen)
    
    # Get the hash method
    method_name = _find_method_hash(em)
    message_hash = compute_hash(message.encode('utf-8'), method_name)
    
    # Reconstruct the expected padded hash
    t = HASH_ASN1[method_name] + message_hash
    em2 = _pad_for_signing(t, klen)

    if len(signature) != klen:
        return False

    # Compare with the signed one
    if em2 != em:
        return False

    return True


if __name__ == '__main__':
    msg = '-----我是芯片人阿伟！-----'
    print("明文 = ", msg)
    print("\n")
    
    e = 0x10001
    n = 0x8394F8C70E1AB4F3F56643EEBEE27C363342E40F2534DD1CFFF7141D5C6AFB047BF814CE326B1FFE2FFEADDCBE19EA9D8AD44BC160B4BB2FED685C374EC192056FCFB10CDD1D1F60EF132E737ED1BC90E366AFCA294CDE3D7EC837146C9937A8BE893D2EC509A3CD8DEA1FE22ED75C5A22D0E5D2732DACEB731586F0DDAEC4D1CA6A7CDB8D720A975E2C6FB26B89BBF4BD7A8AC5EB91721D6038F47D2BABE9BA9F59332342CAE7F6FC479107BBC7F1FBB6403FE3F4C925A9EA00361CF2E263F0757E32CF4A5447010F4B2FE7694FD8FA641925734ADFFFEB0D30F86A3EE5D85FF6843E3BC499727763595BF180D55BFF6752138D1B738890EE85293E2DA5721F
    
    p = 0xB57D58A4811D793E57915C551B8D656B59BE4F682DC4145ADC5770D6EA3FCF4A37D95E5EC46C587A29EC5A6610035169581E039AD6C173D2265D8574A8A251C236B1B0CCB4A900293D417CADD7155D1BAE60C753588476BF308D32FC9BCCE736ABB74D2AB9D2A96EE1DEE54662C91EB3268498BDFD63D063CCBFAC975E8D331714526BC355374A7F
    q = 0xB99A4C9D78D073A74907BE0D15A8C2A9941F2FA3C82CA6354C4362A5976E6EAF6824D2486FE471049B16036EAD291B2E872B9B65FC08D6FA9987BC47756A775AC838B7643A6523BF0E9AB981EFC019115EA54EA46A57B73F94A4B68D49DD0A64943205DD94851E88F49EFC825D7599A7952848D61901C861
    d = 0x65A262CA760580F1D3020BC4D4626269070D4AD4BBFB6A33252EF6B57B16130FB2A5BB844D835B31DE668C6AADD79CD5D54F07B8B576C403501044F25F7DBAC942451D4F7F57284E9A3BA9AC822F84C43131B6E4A32401A1645547DE19C7FB2AF709505DD8CA0A611295DDCCBA3B94D4F6817E93206E0E5B3ED8D6221B7A0AF33849A80AD0DC380C097F36C8035616AAF27C676B48B8A774D6532C14D8DC26FAF6EF548D056C47142C2DC75370BA3D86E7235CD338FB677C782FFB97FB4A3EE72A4B4595F0AEF14E468532046E49894820CCC61E9DCD8131AB54D6B6E35E1C24D967240ADD3D08D6BF8DFC4AED02677978FF5CA102FE33C54598BEE2260D9241
    
    m1 = rsa_encryption(msg, n, e)
    print("RSA加密后的密文 = ", m1)
    print("\n")
    
    m2 = rsa_decryption(m1, n, d)
    print("RSA解密后的明文 = ", m2)
    assert m2 == msg
    print("pass\n")
    
    h1 = rsa_sign(msg, "SHA-512", n, d)
    print("RSA签名结果 = ", h1)
    print("\n")
    
    h2 = rsa_verify(msg, h1, n, e)
    print("RSA验签结果 = ", h2)
    print("pass\n")
    
    