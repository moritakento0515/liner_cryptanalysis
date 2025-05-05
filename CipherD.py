import random

# --- S-box, P-box, parity関数　---
#S-box
SBOX = {
    0x0: 0xF, 0x1: 0xE, 0x2: 0xB, 0x3: 0xC, 0x4: 0x6, 0x5: 0xD, 0x6: 0x7, 0x7: 0x8,
    0x8: 0x0, 0x9: 0x3, 0xA: 0x9, 0xB: 0xA, 0xC: 0x4, 0xD: 0x2, 0xE: 0x1, 0xF: 0x5
}
INV_SBOX = {v: k for k, v in SBOX.items()}

def S(x): return SBOX[x]
def S_inv(x): return INV_SBOX[x]

#P-box
PBOX = {
    0x0: 0x0, 0x1: 0x4, 0x2: 0x8, 0x3: 0xC, 0x4: 0x1, 0x5: 0x5, 0x6: 0x9, 0x7: 0xD,
    0x8: 0x2, 0x9: 0x6, 0xA: 0xA, 0xB: 0xE, 0xC: 0x3, 0xD: 0x7, 0xE: 0xB, 0xF: 0xF
}
INV_PBOX = {v: k for k, v in PBOX.items()}

def P(x): return SBOX[x]
def P_inv(x): return INV_SBOX[x]

#parity
def parity(x, mask):
    """
    mask · x をビット単位で計算し、結果を mod 2 で返す。
    """
    return bin(mask & x).count("1") % 2


def S_layer(x):
    """16ビット入力に4つのS-boxを並列適用"""
    x4 = x & 0b1111
    x3 = (x >> 4) & 0b1111
    x2 = (x >> 8) & 0b1111
    x1 = (x >> 12) & 0b1111
    y1 = S(x1)
    y2 = S(x2)
    y3 = S(x3)
    y4 = S(x4)
    return (y1 << 12) | (y2 << 8) | (y3 << 4) | y4

def S_layer_inv(y):
    """16ビット入力に4つの逆S-boxを並列適用"""
    y4 = y & 0b1111
    y3 = (y >> 4) & 0b1111
    y2 = (y >> 8) & 0b1111
    y1 = (y >> 12) & 0b1111
    x1 = S_inv(y1)
    x2 = S_inv(y2)
    x3 = S_inv(y3)
    x4 = S_inv(y4)
    return (x1 << 12) | (x2 << 8) | (x3 << 4) | x4

def P_layer(x):
    """16ビット入力のP-box関数 (ビット置換)"""
    output = 0
    for i in range(16):
        if (x >> i) & 1:
            output |= (1 << P(i))
    return output

def P_layer_inv(x):
    """16ビット入力の逆P-box関数 (ビット置換)"""
    output = 0
    for i in range(16):
        if (x >> i) & 1:
            output |= (1 << P_inv(i))
    return output



# --- CipherD の実装 ---
def encrypt_cipherD(m, keys):
    """
    CipherD の暗号化関数 (5つの鍵を使用)
      入力: 16ビット平文 m, 鍵タプル keys = (k0, k1, k2, k3, k4) 各16ビット
      処理:
        x0 = m
        # Round 1
        u1 = x0 ^ k0
        v1 = S_layer(u1)
        w1 = P_layer(v1)
        x1 = w1
        # Round 2
        u2 = x1 ^ k1
        v2 = S_layer(u2)
        w2 = P_layer(v2)
        x2 = w2
        # Round 3
        u3 = x2 ^ k2
        v3 = S_layer(u3)
        w3 = P_layer(v3)
        x3 = w3
        # Round 4 (Last round - no P-box)
        u4 = x3 ^ k3
        v4 = S_layer(u4)
        x4 = v4
        # Final Key Addition
        c = x4 ^ k4
    """
    k0, k1, k2, k3, k4 = keys

    # Round 1
    u1 = m ^ k0
    v1 = S_layer(u1)
    x1 = P_layer(v1) # w1 is x1 for next round
    # Round 2
    u2 = x1 ^ k1
    v2 = S_layer(u2)
    x2 = P_layer(v2) # w2 is x2
    # Round 3
    u3 = x2 ^ k2
    v3 = S_layer(u3)
    x3 = P_layer(v3) # w3 is x3
    # Round 4 (Last round)
    u4 = x3 ^ k3
    x4 = S_layer(u4) # v4 is x4
    # Final Key Addition
    c = x4 ^ k4
    return c

def decrypt_cipherD(c, keys):
    """
    CipherD の復号関数 （暗号化処理の逆順を実行）
    """
    k0, k1, k2, k3, k4 = keys

    # Inverse Final Key Addition
    x4 = c ^ k4
    # Inverse Round 4
    u4 = S_layer_inv(x4)
    x3 = u4 ^ k3
    # Inverse Round 3
    w3 = x3
    v3 = P_layer_inv(w3)
    u3 = S_layer_inv(v3)
    x2 = u3 ^ k2
    # Inverse Round 2
    w2 = x2
    v2 = P_layer_inv(w2)
    u2 = S_layer_inv(v2)
    x1 = u2 ^ k1
    # Inverse Round 1
    w1 = x1
    v1 = P_layer_inv(w1)
    u1 = S_layer_inv(v1)
    m = u1 ^ k0
    return m

# --- 線形暗号解析の実装 ---

def linear_attack_cipherD(plaintexts, ciphertexts, MASK_P, MASK_U4, target_epsilon):
    """
    CipherD に対する線形攻撃 (k4の上位4ビットを推定)。
    平文マスク MASK_P, u4マスク MASK_U4 を使用。
    全通りのk4上位4ビットからパリティ値のカウントを行う。
    カウント値の偏り（ε）と目標バイアスとの差(diff)も計算する
    """

    stats = {} # 各k4候補(上位4bit)に対する統計 (count0, count1)

    # k4 の上位4ビット候補 (0x0 から 0xF) を試す
    for key_candidate_prefix in range(16):
        # 候補となるk4を構築 (下位12ビットは0と仮定)
        key_candidate = key_candidate_prefix << 12

        count0 = 0
        count1 = 0
        # 各平文・暗号文ペアで近似式が成り立つかカウント
        for m, c in zip(plaintexts, ciphertexts):
            # k4候補を使って、u4' を計算
            x4_prime = c ^ key_candidate
            u4_prime = S_layer_inv(x4_prime) # 最終ラウンドのS-box層の入力を復元

            # 線形近似式 parity(m, MASK_P) ^ parity(u4', MASK_U4) を計算
            # この値は、正しいk4の場合、ある定数または鍵ビットと高い確率で一致するはず
            # ここでは CIPHER C の例に倣い、値が 0 か 1 かをカウントする
            # (注: 実際の攻撃では、定数項や鍵ビット項を考慮する必要がある場合がある)
            # (注: CIPHER Cの例では ^1 があったが、これはεが負の場合。ここでは仮定しない)
            val = parity(m, MASK_P) ^ parity(u4_prime, MASK_U4)

            # val が 0 か 1 かをカウント
            if val == 0:
                count0 += 1
            else:
                count1 += 1

        total = count0 + count1
        if total == 0: continue # ゼロ除算回避
        major   = max(count0, count1)
        epsilon = major / total - 0.5       # 観測バイアス
        diff    = abs(epsilon - target_epsilon) # 目標バイアスとの差

        stats[key_candidate_prefix] = (count0, count1, epsilon, diff)

    return stats


# --- 実行コード ---

# 近似式に使用するマスク (例: 最上位ビット。適切なマスクは別途線形特性解析で求める必要がある)
# CIPHER C の MASKD に相当
MASK_P = 0x8000 # 平文マスク (例)
MASK_U4 = 0x8000 # 最終ラウンドS-box入力マスク (例)

# 目標とするバイアス (ε)
# (注: これは仮の値。実際の値はCipherDの線形特性に依存する)
# CIPHER D の元コードの計算結果 0.015625 を参考に設定 (絶対値)
# target_epsilon = 0.015625
# CIPHER C の例に合わせて設定
target_epsilon = abs(1/2 - 3/8) # CIPHER C Sbox のバイアス例 (ここでは仮)

# 乱数で秘密鍵を設定（各鍵は 16 ビット）
# 鍵タプル keys = (k0, k1, k2, k3, k4)
secret_key = tuple(random.randint(0, 2**16 - 1) for _ in range(5))

# 元のコードの鍵を使用する場合 (コメントアウト解除)
# secret_key = (0x5b92, 0x064b, 0x1e03, 0xa55f, 0xecbd)

# N 個の既知平文・暗号文ペアを生成する
N = 10000 # 必要なペア数は偏りの大きさに依存 (16ビットブロックなので最大2^16個の異なる平文)
plaintexts = []
ciphertexts = []
# 既知平文をランダムに生成 (重複を許容)
for _ in range(N):
    m = random.randint(0, 2**16 - 1)
    c = encrypt_cipherD(m, secret_key)
    plaintexts.append(m)
    ciphertexts.append(c)

# (オプション) 全ての平文を使用する場合 (N=2**16)
# N = 2**16
# plaintexts = list(range(N))
# ciphertexts = [encrypt_cipherD(m, secret_key) for m in plaintexts]


# 線形攻撃の実行 (k4の上位4ビットを推定)
stats = linear_attack_cipherD(plaintexts, ciphertexts, MASK_P, MASK_U4, target_epsilon)

print(f"--- Linear Attack on CipherD (Estimating k4[15:12]) ---")
print(f"Using {N} plaintext/ciphertext pairs.")
print(f"Plaintext Mask: {hex(MASK_P)}, U4 Mask: {hex(MASK_U4)}")
print(f"Target epsilon: {target_epsilon:.5f}\n")

# 結果をバイアスの差 (diff) が小さい順にソートして表示
sorted_stats = sorted(stats.items(), key=lambda item: item[1][3])

print("Key Candidate (k4[15:12]), Count0, Count1, Observed Epsilon, Diff from Target")
for key_candidate_prefix, (count0, count1, epsilon, diff) in sorted_stats:
    print(f"           {key_candidate_prefix:#0{3}x}           , {count0:6d}, {count1:6d}, {epsilon: .5f},        {diff:.5f}")

print("\nSecret keys (k0, k1, k2, k3, k4):")
print(f"k0: {secret_key[0]:#06x}")
print(f"k1: {secret_key[1]:#06x}")
print(f"k2: {secret_key[2]:#06x}")
print(f"k3: {secret_key[3]:#06x}")
print(f"k4: {secret_key[4]:#06x}")

correct_k4_prefix = (secret_key[4] >> 12) & 0xF
print(f"\nCorrect k4 prefix (k4[15:12]): {correct_k4_prefix:#0{3}x}")

# 最も可能性の高い鍵候補を表示
most_likely_key_prefix = sorted_stats[0][0]
print(f"Most likely k4 prefix found by attack: {most_likely_key_prefix:#0{3}x}")

if most_likely_key_prefix == correct_k4_prefix:
    print("Attack successful: Correct k4 prefix identified.")
else:
    print("Attack failed: Correct k4 prefix not identified (may need more data, better masks, or different target epsilon).")