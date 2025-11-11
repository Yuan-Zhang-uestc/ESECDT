import bplib.bp as bp
from petlib.bn import Bn

class EncryptionSDK:
    def __init__(self):
        self.group = bp.BpGroup()
        self.g1 = self.group.gen1()
        self.h1 = self.group.gen2()
        self.gt = self.group.pair(self.g1, self.h1)
    
    def genenrate_key(self):
        sk0 = self.group.order().random()
        sk1 = self.group.order().random()
        # print(sk0)
        # print(sk1)
        pk0 = self.g1 * sk0
        pk1 = self.g1 * sk1
        return sk0, sk1, pk0, pk1

    def generate_hb(self):
        b = self.group.order().random()
        hb = self.h1 * b
        return b, hb

    def generate_re_encrypt_key(self, hb, a0, ar):
        order = self.group.order()
        a0_inverse = a0.mod_inverse(order)
        # print(a0_inverse)
        # print((a0_inverse * a0) % order)
        rk = hb * ((ar * a0_inverse) % order)
        return rk
    
    def encrypt1(self, apkr, message):
        k = self.group.order().random()
        z_ark = (self.group.pair(apkr, self.h1)) ** k
        z_k = (self.group.pair(self.g1, self.h1)) ** k

        k1 = self.group.order().random()
        gt_k1 = self.gt ** k1
        # print(gt_k1.export())

        beta = gt_k1 * z_k

        gt_k1_bytes = gt_k1.export()

        # 将字节串转换为数字
        gt_k1_int = int.from_bytes(gt_k1_bytes, byteorder='big')

        # 将消息转换为字节
        message_bytes = message.encode('utf-8')

        # 将字节转换为数字
        message_int = int.from_bytes(message_bytes, byteorder='big')
        c_int = gt_k1_int+ message_int

        return(z_ark, beta, c_int)

    def encrypt2(self, apkr, apk0, message):
        k = self.group.order().random()
        z_ark = (self.group.pair(apkr, self.h1)) ** k
        g_a0k = apk0 * k

        k1 = self.group.order().random()
        gt_k1 = self.gt ** k1

        beta = gt_k1 * z_ark

        gt_k1_bytes = gt_k1.export()

        # 将字节串转换为数字
        gt_k1_int = int.from_bytes(gt_k1_bytes, byteorder='big')

        # 将消息转换为字节
        message_bytes = message.encode('utf-8')

        # 将字节转换为数字
        message_int = int.from_bytes(message_bytes, byteorder='big')
        c_int = gt_k1_int+ message_int

        return(g_a0k, beta, c_int)

    def re_encrypt(self,rk, c):
        g_a0k = c[0]
        beta = c[1]
        c_int = c[2]

        z_bark = self.group.pair(g_a0k, rk)
        return(z_bark, beta, c_int)

    def decrypt1(self, ar, c):
        alpha = c[0]
        beta = c[1]
        c_int = c[2]

        order = self.group.order()
        ar_inverse = ar.mod_inverse(order)
        # print((ar_inverse * ar) % order)

        gt_k1 = beta * (alpha ** ar_inverse).inv()
        # print(gt_k1.export())
        gt_k1_bytes = gt_k1.export()

        gt_k1_int = int.from_bytes(gt_k1_bytes, byteorder='big')
        message_int = c_int - gt_k1_int

        # 计算字节的长度
        byte_length = (message_int.bit_length() + 7) // 8

        # 将数字转换为字节
        message_bytes = message_int.to_bytes(byte_length, byteorder='big')


        # 将字节解码为消息
        message = message_bytes.decode('utf-8')
        return message

    def decrypt2(self, ar, a0, c):
        alpha = c[0]
        beta = c[1]
        c_int = c[2]

        order = self.group.order()
        a0_inverse = a0.mod_inverse(order)
        gt_k1 = beta * (self.group.pair((alpha * a0_inverse), self.h1) ** ar).inv()
        gt_k1_bytes = gt_k1.export()

        gt_k1_int = int.from_bytes(gt_k1_bytes, byteorder='big')
        message_int = c_int - gt_k1_int

        # 计算字节的长度
        byte_length = (message_int.bit_length() + 7) // 8

        # 将数字转换为字节
        message_bytes = message_int.to_bytes(byte_length, byteorder='big')


        # 将字节解码为消息
        message = message_bytes.decode('utf-8')
        return message

if __name__ == "__main__":
    
    sdk = EncryptionSDK()

    ar, a0, apkr, apk0 = sdk.genenrate_key()#生成A的公私钥
    br, b0, bpkr, bpk0 = sdk.genenrate_key()#生成B的公私钥
    
    b, hb = sdk.generate_hb()#B选择b，公布hb

    rk = sdk.generate_re_encrypt_key(hb,a0,ar)#A根据hb计算重加密密钥
    
    # 获取用户输入的消息
    message = input("请输入消息: ")
    
    #测试加密函数encrypt1
    c1 = sdk.encrypt1(apkr, message)
    # print("密文是：",c1)
    m = sdk.decrypt1(ar, c1)
    # print("明文是：",m)

    #测试加密函数encrypt2以及代理重加密
    c2 = sdk.encrypt2(apkr, apk0, message)
    # print(c2)
    c3 = sdk.re_encrypt(rk,c2)
    m2 = sdk.decrypt2(ar, a0, c2)
    print("发送给A的明文是：",m2)
    m3 = sdk.decrypt1(b, c3)
    print("发送给B的明文是：",m3)