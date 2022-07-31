
from gmssl import sm3, func
import random
import struct
secret = str(random.random())
secret_hash = sm3.sm3_hash(func.bytes_to_list(bytes(secret, encoding='utf-8')))
secret_len = len(secret)
append_m = "1234567890"   # 附加消息
pad_str = ""
pad = []
def generate_guess_hash(old_hash, secret_len, append_m):
    vectors = []
    message = ""
    for r in range(0, len(old_hash), 8):
        vectors.append(int(old_hash[r:r + 8], 16))
    if secret_len > 64:
        for i in range(0, int(secret_len / 64) * 64):
            message += 'p'
    for i in range(0, secret_len % 64):
        message += 'p'
    message = func.bytes_to_list(bytes(message, encoding='utf-8'))
    message = padding(message)
    message.extend(func.bytes_to_list(bytes(append_m, encoding='utf-8')))
    return sm3_re(message, vectors)
def CF(V,M,i):#压缩函数
    A,B,C,D,E,F,G,H = V[i]
    W,W_ = Expand(M,i)
    for j in range(64):
        SS1 = ROL((ROL(A,12)+E+ROL(T_(j),j%32))%(2**32),7)
        SS2 = SS1 ^ ROL(A,12)
        TT1 = (FF(A,B,C,j)+D+SS2+W_[j])%(2**32)
        TT2 = (GG(E,F,G,j)+H+SS1+W[j])%(2**32)
        D = C
        C = ROL(B,9)
        B = A
        A = TT1
        H = G
        G = ROL(F,19)
        F = E
        E = P0(TT2)
        #print("j={}:".format(j))
        #print(hex(A),hex(B),hex(C),hex(D),hex(E),hex(F),hex(G),hex(H))
    a,b,c,d,e,f,g,h = V[i]
    V_ = [a^A,b^B,c^C,d^D,e^E,f^F,g^G,h^H]
    return V_
def sm3_re(msg, new_v):
    # print(msg)
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64
    for i in range(reserve1, range_end):
        msg.append(0x00)
    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])
    group_count = round(len(msg) / 64) - 1
    B = []
    for i in range(0, group_count):
        B.append(msg[(i + 1)*64:(i+2)*64])
    V = []
    V.append(new_v)
    for i in range(0, group_count):
        V.append(CY(V[i], B[i],i))
    y = V[i+1]
    result = ""
    for i in y:
        result = '%s%08x' % (result, i)
    return result
def padding(msg):
    mlen = len(msg)
    msg.append(0x80)
    mlen += 1
    tail = mlen % 64
    range_end = 56
    if tail > range_end:
        range_end = range_end + 64
    for i in range(tail, range_end):
        msg.append(0x00)
    bit_len = (mlen - 1) * 8
    msg.extend([int(x) for x in struct.pack('>q', bit_len)])
    for j in range(int((mlen - 1) / 64) * 64 + (mlen - 1) % 64, len(msg)):
        global pad
        pad.append(msg[j])
        global pad_str
        pad_str += str(hex(msg[j]))
    return msg
guess_hash = generate_guess_hash(secret_hash, secret_len, append_m)
new_msg = func.bytes_to_list(bytes(secret, encoding='utf-8'))
new_msg.extend(pad)
new_msg.extend(func.bytes_to_list(bytes(append_m, encoding='utf-8')))
new_msg_str = secret + pad_str + append_m
new_hash = smm3(new_msg)
print("隐藏的消息: "+secret)
print("已知的消息长度:%d" % len(secret))
print("已知的消息哈希:" + secret_hash)
print("附加消息:", append_m)
print("伪造的哈希值:" + guess_hash)
print("验证攻击是否成功")
print("计算hash(secret+padding+m')")
print("new message: \n" + new_msg_str)
print("hash(new message):" + new_hash)
if new_hash == guess_hash:
    print("success!")
else:
    print("fail..")
