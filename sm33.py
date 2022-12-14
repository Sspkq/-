#SM3
import time
import random
IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

def ROL(X,i):#循环左移
    i = i % 32
    return ((X<<i)&0xFFFFFFFF) | ((X&0xFFFFFFFF)>>(32-i))
def FF(X,Y,Z,j):#FF布尔函数
    if j>=0 and j<=15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (X & Z) | (Y & Z))
def GG(X,Y,Z,j):#GG布尔函数
    if j>=0 and j<=15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (~X & Z))
def P0(X):#置换函数P0
    return X^ROL(X,9)^ROL(X,17)
def P1(X):#置换函数P1
    return X^ROL(X,15)^ROL(X,23)
def T_(j):#常量
    if j>=0 and j<=15:
        return 0x79cc4519
    else:
        return 0x7a879d8a
def Fill(message):#填充消息
    m = bin(int(message,16))[2:]
    if len(m) != len(message)*4:
        m = '0'*(len(message)*4-len(m)) + m
    l = len(m)
    l_bin = '0'*(64-len(bin(l)[2:])) + bin(l)[2:]
    m = m + '1'
    m = m + '0'*(448-len(m)%512) + l_bin
    m = hex(int(m,2))[2:]
    #print("填充后的消息为:",m)
    return m
def Group(m):
    n = len(m)/128
    M = []
    for i in range(int(n)):
        M.append(m[0+128*i:128+128*i])
    return M
def Expand(M,n):#消息扩展
    W = []
    W_ = []
    for j in range(16):#十六组
        W.append(int(M[n][0+8*j:8+8*j],16))
    for j in range(16,68):
        W.append(P1(W[j-16]^W[j-9]^ROL(W[j-3],15))^ROL(W[j-13],7)^W[j-6])
    for j in range(64):
        W_.append(W[j]^W[j+4])
    Wstr = ''
    W_str = ''
    for x in W:
        Wstr += (hex(x)[2:] + ' ')
    for x in W_:
        W_str+= (hex(x)[2:] + ' ')
    #print("第{}个消息分组 扩展后消息：".format(n+1))
    #print("W:",Wstr)
    #print("W':",W_str)
    return W,W_

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

def Iterate(M):
    n = len(M)
    V = []
    V.append(IV)
    for i in range(n):
        V.append(CF(V,M,i))
    return V[n]

def smm3(m):
    p=Fill(m)
    pp=Group(p)
    ppp=Iterate(pp)
    result = ''
    print(ppp)
    for x in ppp:
        result += (hex(x)[2:])
    print("对应的杂凑值:",result)
    return result


def decimalToHex(decValue):
    hex=""
    while decValue !=0:
        hexValue=decValue%16   #求余数
        hex=toHexChar(hexValue)+hex
        decValue=decValue//16  #求商
    return hex

def toHexChar(hexValue):
    if 0<=hexValue<=9:
        return chr(hexValue+ord('0'))
    else:
        return chr(hexValue-10+ord('A'))

def biratt(n):
    x=decimalToHex(random.randint(0,2**512))
    x0=smm3(x)
    x1=x0.replace(" ","")
    print("aa",x1)
    x1=smm3(x1)
    print("bb",x1)
    for i in range(2**n):
        hexn=n//8
        if(x1[:hexn]==x0[:hexn]):
            x1=x0
            x0=x
            for j in range(i):
                print('gtj',x0)
                print('yy',smm3(x0))
                print('gj',smm3(x0)[:hexn])
                if(smm3(x0)[:hexn]==smm3(x1)[:hexn]):
                    print('j:',j)
                    print("找到一对碰撞,x0:",x0,"x1:",x1)
                    return 0
                else:
                    x0=smm3(x0)
                    x1=smm3(x1)
st=time.time()
biratt(64)
nd=time.time()
print("找到碰撞的时间为",nd-st)
