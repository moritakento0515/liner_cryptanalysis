import random


# --- S-box, parity 関数　---
SBOX = {
    0x0: 0xF, 0x1: 0xE, 0x2: 0xB, 0x3: 0xC, 0x4: 0x6, 0x5: 0xD, 0x6: 0x7, 0x7: 0x8,
    0x8: 0x0, 0x9: 0x3, 0xA: 0x9, 0xB: 0xA, 0xC: 0x4, 0xD: 0x2, 0xE: 0x1, 0xF: 0x5
}
INV_SBOX = {v: k for k, v in SBOX.items()}

def S(x): return SBOX[x]
def S_inv(x): return INV_SBOX[x]

def parity(x, mask):
    """
    mask · x をビット単位で計算し、結果を mod 2 で返す。
    """
    return bin(mask & x).count("1") % 2

# --- CipherC の実装 ---
def encrypt_cipherC(m, keys):
    """
    CipherC の暗号化関数
      入力: 4ビット平文 m, 鍵タプル keys = (k0, k1, k2, k3) 各4ビット
      処理:
         u = m ⊕ k0
         v = S(u)
         w = v ⊕ k1
         x = S(w)
         y = x ⊕ k2
         z = S(y)
         c = z ⊕ k3
      出力: 4ビット暗号文 c
    """
    k0, k1, k2, k3 = keys
    u = m ^ k0
    v = S(u)
    w = v ^ k1
    x = S(w)
    y = x ^ k2
    z = S(y)
    c = z ^ k3
    return c 

# decrypt_cipherC は攻撃コードでは直接使用しませんが、参考のために残します
def decrypt_cipherC(c, key):
    """
    CipherC の復号関数（暗号化処理の逆順を実行）
    """
    k0 = (key >> 12) & 0xF
    k1 = (key >> 8) & 0xF
    k2 = (key >> 4) & 0xF
    k3 = key & 0xF
    z = c ^ k3
    y = S_inv(z)
    x = y ^ k2
    w = S_inv(x)
    v = w ^ k1
    u = S_inv(v)
    m = u ^ k0
    return m 


# --- 線形暗号解析の実装 ---

def linear_attack(plaintexts, ciphertexts):
    """
    CipherC に対する線形攻撃 (k3を推定)。
    平文マスク a=0xD, y'マスク d=0xD を使用。
    全通りのk3からパリティ値のカウントを行う。
    カウント値の偏り（ε）と目標バイアスとの差(diff)も計算する
    """

    stats = {} # 各k3候補に対する統計 (count0, count1)

    # k3 の全候補 (0x0 から 0xF) を試す
    for key_candidate in range(16):
        count0 = 0
        count1 = 0
        # 各平文・暗号文ペアで近似式が成り立つかカウント
        for m, c in zip(plaintexts, ciphertexts):
            # k3候補を使って、y' を計算
            z_prime = c ^ key_candidate
            y_prime = S_inv(z_prime)
            
            # 線形近似式 parity(m, d) ^ parity(w', d) ^ 1 を計算(εがーだから)
            # この値は、正しいk2の場合、ある未知の鍵ビットのパリティと高い確率で一致するはず
            val = parity(m, MASKD) ^ parity(y_prime, MASKD) ^ 1
            # val が 0 か 1 かをカウント
            if val == 0:
                count0 += 1
            else:
                count1 += 1
        total = count0 + count1
        major   = max(count0, count1)
        epsilon = major / total - 0.5       # 観測バイアス
        diff    = abs(epsilon - target_epsilon)

        stats[key_candidate] = (count0,count1,epsilon,diff)

    return stats


# --- 実行コード ---

# d = 0xd (1101₂) を使用
MASKD = 0xD
#（MASKDを用いた場合のBの線形特性確率）-1/2　　　　　（目標バイアス）
target_epsilon = (1/2+9/32) - (1/2)

# 乱数（または固定値）で秘密鍵を設定（各鍵は 4 ビット）
secret_key = (random.randint(0,2**16-1))
secret_key =(                   #秘密鍵を分割
    (secret_key >> 12) & 0xF,   #k0
    (secret_key >> 8) & 0xF,    #k1
    (secret_key >> 4) & 0xF,    #k2
    secret_key & 0xF            #k3
)

# N 個の既知平文・暗号文ペアを生成する
N = 2000  # 必要なペア数は偏りの大きさに依存
plaintexts = []
ciphertexts = []
for _ in range(N):
    m = random.randint(0, 15)
    # m = _
    c = encrypt_cipherC(m, secret_key)
    plaintexts.append(m)
    ciphertexts.append(c)

# 線形攻撃の実行
stats = linear_attack(plaintexts, ciphertexts)
for key_candidate, (count0,count1,epsilon,diff) in stats.items():
    print(f"{key_candidate=}, cnt0={count0}, cnt1={count1}, ε={epsilon:.5f}, diff={diff:.5f}")

print("\nSecret keys (k0, k1, k2, k3):", secret_key)
print(f"Target epsilon: {target_epsilon:.5f}")    
# 正しい (k0 ⊕ k1 ⊕ k2) ⋅ d の値を計算して比較
true_key_xor = secret_key[0] ^ secret_key[1] ^ secret_key[2]
true_bit     = parity(true_key_xor, MASKD)
print("Correct bit (k0 ⊕ k1 ⊕ k2) ⋅ d:", true_bit)