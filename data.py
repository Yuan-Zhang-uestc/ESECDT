import os

def generate(size):
    return os.urandom(size).hex()

if __name__ == "__main__":
    size = 16
    data = generate(size)
    print("随机数据：", data)