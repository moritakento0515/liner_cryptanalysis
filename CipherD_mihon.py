Sbox = [0xf, 0xe, 0xb, 0xc, 0x6, 0xd, 0x7,0x8, 0x0, 0x3, 0x9, 0xa, 0x4, 0x2, 0x1, 0x5]
Sbox_inv = [0x8, 0xe, 0xd, 0x9, 0xc, 0xf, 0x4, 0x6, 0x7, 0xa, 0xb, 0x2, 0x3, 0x5, 0x1, 0x0]
Pbox = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10 ,14, 3, 7, 11, 15]


def round(m, k):
    # add key
    m ^= k

    m4 = m & 0b1111
    m3 = (m>>4) & 0b1111
    m2 = (m>>8) & 0b1111
    m1 = (m>>12) & 0b1111

    # Sbox
    x1 = Sbox[m1]
    x2 = Sbox[m2]
    x3 = Sbox[m3]
    x4 = Sbox[m4]

    ans = [0] * 16

    # Permutation
    for i in range(4):
        ans[Pbox[i]] = (x4 >> i) & 1
        ans[Pbox[i+4]] = (x3 >> i) & 1
        ans[Pbox[i+8]] = (x2 >> i) & 1
        ans[Pbox[i+12]] = (x1 >> i) & 1

    ans.reverse()
    return int("".join(map(str, ans)), 2)
    
def last_round(m, k):
    m ^= k

    m4 = m & 0b1111
    m3 = (m>>4) & 0b1111
    m2 = (m>>8) & 0b1111
    m1 = (m>>12) & 0b1111
    x1 = Sbox[m1]
    x2 = Sbox[m2]
    x3 = Sbox[m3]
    x4 = Sbox[m4]

    ans = x4 + (x3<<4) + (x2<<8) + (x1<<12)

    return ans

def encrypt(message):
    y1 = round(message, k0)
    y2 = round(y1, k1)
    y3 = round(y2, k2)
    y4 = last_round(y3, k3)
    cipher_text = y4 ^ k4
    return cipher_text

calc_bit = lambda x: bin(x).count("1") % 2

k0 = 0x5b92
k1 = 0x064b
k2 = 0x1e03
k3 = 0xa55f
k4 = 0xecbd

mask = 0x8000
right = (k0&mask)^(k1&mask)^(k2&mask)^(k3&mask)^(k4&mask)
count = 0

for i in range(2**16):
    if calc_bit((mask & i) ^ (mask & encrypt(i))) == calc_bit(right):
        count += 1

print(count/2**16-0.5)