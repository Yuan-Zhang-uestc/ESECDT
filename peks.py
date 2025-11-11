import bplib.bp as bp
from Crypto.Util.number import inverse
from petlib.bn import Bn
import hashlib

def generate_key(group, g):
    sk = group.order().random()
    pk = sk * g
    return sk, pk

def hash1(group, m):
    hm = group.hashG1(m.encode())
    return hm

def hash2(group, gt):
    gt_bytes = gt.export()
    gt_int = Bn.from_binary(gt_bytes)
    zp_elem = gt_int.mod(group.order())
    return zp_elem

def G1toInt(g1):
    g1_bytes = g1.export()
    hash_value = hashlib.sha256(g1_bytes).digest()
    g1_int = Bn.from_binary(hash_value)
    return g1_int

def sha256(w):
    w_bytes = w.encode('utf-8')
    # 使用 hashlib 计算 SHA-256 哈希值
    hash_object = hashlib.sha256(w_bytes)
    # 返回十六进制表示的哈希值
    return hash_object.hexdigest()

def hashH(hw, sigma):
    # 将 hw 和 sigma 拼接为一个字符串
    combined = str(hw) + str(sigma)
    # 转换为字节类型并计算 SHA-256 哈希值
    hash_value = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    return hash_value

def random(group):
    r = group.order().random()
    return r

def sign(sk, m):
    sigma = sk * m
    return sigma

class SA_PEKSSDK_Server:
    def __init__(self, group, g):
        self.group = group
        self.g = g
        self.sk, self.pk = generate_key(self.group, self.g)


if __name__ == "__main__":
    group = bp.BpGroup()
    g = group.gen2()
    server = SA_PEKSSDK_Server(group, g)
    sk, pk = generate_key(group, g)

    w = "BLS"
    hw = hash1(group, w)
    r = random(group)
    hwr = hw * r
    sigm_hwr = sign(server.sk,hwr)
    sigm_hw = G1toInt(sigm_hwr * r.mod_inverse(group.order()))
    ksdw = hashH(sha256(w), sigm_hw)
    
    r1 = random(group)
    h1w = hash1(group, ksdw)
    t = group.pair(h1w, pk * r1)
    ctw = (g * r1, hash2(group, t))

    Tw = hash1(group, ksdw) * sk
    query = hash2(group, group.pair(Tw, ctw[0]))
    print(query == ctw[1])
    

    