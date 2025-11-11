import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import bplib.bp as bp
import base64
import proxy_re_encrypt_sdk
import time
import peks
import data

# 生成公共参数
def generate_parameters():
    # 初始化双线性对群
    group = bp.BpGroup()
    
    # 生成 G1 和 G2 中的基元
    g1 = group.gen1()
    g2 = group.gen2()
    return group, g1, g2

# 生成公私钥对
def generate_key_pair(group, g2):
    private_key = group.order().random()
    public_key = private_key * g2
    return private_key, public_key


# 交换生成共享密钥
def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key * peer_public_key
    return shared_key

# 随机生成 AES-GCM 加密密钥
def generate_datakey(length=32):
    """
    生成一个随机的 AES-GCM 加密密钥。
    
    :param length: 密钥的字节长度，默认是 32 字节（256 位）。
    :return: 随机生成的 AES-GCM 加密密钥（字节类型）。
    """
    return os.urandom(length)

# HKDF 用于密钥派生
def hkdf(key_material, length=32, salt=None, info=b'ratchet'):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    full_output = hkdf.derive(key_material)
    return full_output


# 使用 AES-GCM 加密消息
def encrypt_message_aesgcm(key, message, associated_data=b'', type = 0):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM 需要 96 位 (12 字节) 的随机 nonce
    if type == 0:
        ciphertext = aesgcm.encrypt(nonce, message, associated_data)
    else:
        ciphertext = aesgcm.encrypt(nonce, message.encode(), associated_data)
    return nonce, ciphertext



# 使用 AES-GCM 解密消息
def decrypt_message_aesgcm(key, nonce, ciphertext, associated_data=b'', type = 0):
    aesgcm = AESGCM(key)
    if type == 0:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    else:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data).decode()
    return plaintext

def encrypt_message_aescbc(key, message):
    """
    使用 AES-CBC 加密消息
    :param key: AES 密钥 (16、24 或 32 字节)
    :param message: 要加密的消息（字节类型）
    :return: (nonce, ciphertext)
    """
    # 将字符串消息转换为字节类型
    message_bytes = message.encode('utf-8')

    # 生成 16 字节的随机 IV（初始化向量）
    iv = os.urandom(16)
    # start_time = time.time()
    # 创建 AES-CBC 加密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    
    encryptor = cipher.encryptor()


    # 使用 PKCS7 填充
    padder = PKCS7(128).padder()
    padded_message = padder.update(message_bytes) + padder.finalize()

    # 加密消息
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # end_time = time.time()
    # print("加密耗时：",end_time - start_time,"s")

    return iv, ciphertext

def decrypt_message_aescbc(key, iv, ciphertext):
    """
    使用 AES-CBC 解密消息
    :param key: AES 密钥 (16、24 或 32 字节)
    :param iv: 初始化向量 (IV)
    :param ciphertext: 密文（字节类型）
    :return: 解密后的明文消息
    """
    # 创建 AES-CBC 解密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # 解密消息
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    # 使用 PKCS7 去填充
    unpadder = PKCS7(128).unpadder()
    message_bytes = unpadder.update(padded_message) + unpadder.finalize()

    return message_bytes.decode('utf-8')

def tranBytesToStirng(bytes):
    encoded_bytes = base64.b64encode(bytes).decode('utf-8')
    return encoded_bytes

def transStringToBytes(s):
    decoded_string = base64.b64decode(s)
    return decoded_string

class Exchange:
    def __init__(self, group, g2):
        self.storage = []
        self.sk, self.pk = peks.generate_key(group, g2)
    
    # 存储方法
    def store(self, keyword_ciphertexts, upload1):
        # 将 keyword_ciphertext 作为键，upload1 作为值存储到字典中
        self.storage.append([keyword_ciphertexts, upload1])


if __name__ == "__main__":
    # 生成公共参数(g1, g2)
    group, g1, g2 = generate_parameters()
    
    PREsdk = proxy_re_encrypt_sdk.EncryptionSDK()
    
    # 生成500MB数据
    data1 = data.generate(1024 * 1024 * 500)
    keywords = ["test1", "test2","test3"]

    # 初始化交易所
    exchange = Exchange(group, g2)
    # broker 生成密钥对
    broker_sk, broker_pk = generate_key_pair(group, g2)

    br, b0, bpkr, bpk0 = PREsdk.genenrate_key() #生成broker的公私钥
    buyer_r, buyer_0, buyer_pkr, buyer_pk0 = PREsdk.genenrate_key() #生成buyer的公私钥
    # 平均耗时
    duration = 0
    delegate = 0
    DRcv = 0
    retrieve = 0
    deliver = 0
    BRcv = 0
    for i in range(20):    
        start_time = time.time()

        # seller 生成密钥对
        seller_sk, seller_pk = generate_key_pair(group, g2)

        shared_key_s = generate_shared_key(seller_sk, broker_pk)
        message_key_s = hkdf(shared_key_s.export())
        data_key = generate_datakey()

        nonce1, data_key_encryption = encrypt_message_aesgcm(message_key_s, data_key)

        # seller 加密数据
        nonce, ciphertext = encrypt_message_aescbc(data_key, data1)
        keyword_ciphertexts = []
        # 生成可搜索加密关键词
        for keyword in keywords:
            keywordG1 = peks.hash1(group, keyword)
            blindr = peks.random(group)
            keywordG1blind = keywordG1 * blindr
            sign_keywordG1blind = peks.sign(exchange.sk, keywordG1blind)
            sign_keyword = peks.G1toInt(sign_keywordG1blind * blindr.mod_inverse(group.order()))
            real_keyword = peks.hashH(peks.sha256(keyword), sign_keyword)

            # 生成可搜索加密密文
            encrypt_r = peks.random(group)
            real_keywordG1 = peks.hash1(group, real_keyword)
            t = group.pair(real_keywordG1, broker_pk * encrypt_r)
            keyword_ciphertext = (g2 * encrypt_r, peks.hash2(group, t))
            keyword_ciphertexts.append(keyword_ciphertext)
        
        delegate += time.time() - start_time
        start_time1 = time.time()

        # 加密数据密钥
        shared_key_b = generate_shared_key(broker_sk, seller_pk)
        message_key_b = hkdf(shared_key_b.export())
        data_key_decryption = decrypt_message_aesgcm(message_key_b, nonce1, data_key_encryption)
        encoded_key = tranBytesToStirng(data_key)
        encoded_key_ciphertext1 = PREsdk.encrypt2(bpkr, bpk0, encoded_key)
        upload1 = (nonce, ciphertext, encoded_key_ciphertext1)

        
        # 将关键词密文和加密数据存储到交易所中
        exchange.store(keyword_ciphertexts, upload1)

        DRcv += time.time() - start_time1
        start_time2 = time.time()

        # 搜索
        # 生成可搜索加密关键词
        s_keywordG1 = peks.hash1(group, keywords[0])
        s_blindr = peks.random(group)
        s_keywordG1blind = s_keywordG1 * s_blindr
        s_sign_keywordG1blind = peks.sign(exchange.sk, s_keywordG1blind)
        s_sign_keyword = peks.G1toInt(s_sign_keywordG1blind * s_blindr.mod_inverse(group.order()))
        s_real_keyword = peks.hashH(peks.sha256(keywords[0]), s_sign_keyword)

        s_real_keyword_trapdoor = peks.hash1(group, s_real_keyword) * broker_sk
        search = []
        for items in exchange.storage:
            for keyword_ciphertext in items[0]:
                if(peks.hash2(group, group.pair(s_real_keyword_trapdoor, keyword_ciphertext[0])) == keyword_ciphertext[1]):
                    print("found!")
                    search.append(items[1])

        retrieve += time.time() - start_time2
        start_time3 = time.time()

        buyer_b, buyer_hb = PREsdk.generate_hb() #buyer选择buyer_b，公布buyer_hb
        rk = PREsdk.generate_re_encrypt_key(buyer_hb, b0, br) #broker根据buyer_hb计算重加密密钥
        
        encoded_key_ciphertext2 = PREsdk.re_encrypt(rk, search[0][2])
        
        deliver += time.time() - start_time3
        start_time4 = time.time()

        encoded_key_de = PREsdk.decrypt1(buyer_b, encoded_key_ciphertext2)
        key = transStringToBytes(encoded_key_de)
        d = decrypt_message_aescbc(key, search[0][0], search[0][1])
        
        BRcv += time.time() - start_time4

        end_time = time.time()
        durationi = end_time - start_time
        print("解密是否正确：", d == data1)
        print("耗时：", durationi, "s")
        duration += durationi
    
    print("delegate耗时：", delegate / 20, "s")
    print("DRcv耗时：", DRcv / 20, "s")
    print("retrieve耗时：", retrieve / 20, "s")
    print("deliver耗时：", deliver / 20, "s")
    print("BRcv耗时：", BRcv / 20, "s")
    print("总耗时：", duration, "s")


