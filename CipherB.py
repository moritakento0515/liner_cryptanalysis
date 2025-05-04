import random
import math


# --- S-box, parity 関数 (変更なし) ---
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

# --- CipherB (3ラウンド暗号) の実装 ---
def encrypt_cipherB(m, keys):
    """
    CipherB の暗号化関数 (3つの鍵を使用)
      入力: 4ビット平文 m, 鍵タプル keys = (k0, k1, k2) 各4ビット
      処理: u = m⊕k0, v = S(u), w = v⊕k1, x = S(w), c = x⊕k2
    """
    k0, k1, k2 = keys
    u = m ^ k0
    v = S(u)
    w = v ^ k1
    x = S(w)
    c = x ^ k2
    return c 

# decrypt_cipherB は攻撃コードでは直接使用しませんが、参考のために残します
def decrypt_cipherB(c, keys):
    """
    CipherB の復号関数 (3つの鍵を使用)
    """
    if len(keys) != 3:
        raise ValueError(f"decrypt_cipherB requires 3 keys, but got {len(keys)}")
    k0, k1, k2 = keys
    x = c ^ k2
    w = S_inv(x)
    v = w ^ k1
    u = S_inv(v)
    m = u ^ k0
    return m 

target_epsilon = 14/16 - 0.5  # ≒-0.28125 

# --- 線形暗号解析の実装 ---
# 今回は、文献で d = 0xd (1101₂) として選んでいるマスクを利用
MASKD = 0xD

def linear_attack(plaintexts, ciphertexts):
    """
    CipherB に対する線形攻撃 (k2を推定)。
    平文マスク a=0xD, w'マスク d=0xD を使用。
    観測されたバイアス偏差が最大の k2 候補を選択する。
    """

    stats = {} # 各k2候補に対する統計 (count0, count1)

    # k2 の全候補 (0x0 から 0xF) を試す
    for candidate in range(16):
        count0 = 0
        count1 = 0
        # 各平文・暗号文ペアで近似式が成り立つかカウント
        for m, c in zip(plaintexts, ciphertexts):
            # k2候補を使って、w' を計算
            x_prime = c ^ candidate
            w_prime = S_inv(x_prime)
            
            # 線形近似式 parity(m, d) ^ parity(w', d) ^ 1 を計算
            # この値は、正しいk2の場合、ある未知の鍵ビットのパリティと高い確率で一致するはず
            val = parity(m, MASKD) ^ parity(w_prime, MASKD) ^ 1
            # val が 0 か 1 かをカウント
            if val == 0:
                count0 += 1
            else:
                count1 += 1
        stats[candidate] = (count0, count1)

    # --- 観測されたバイアスが目標バイアスに最も近い k2 を選ぶ ---
    best_candidate = None
    best_epsilon   = None           # 実際に記録する ε
    best_diff      = float("inf")   # |ε - ε_target| の最小値

    for candidate, (cnt0, cnt1) in stats.items():
        total = cnt0 + cnt1
        if total == 0:
            # ペア数ゼロならスキップ
            continue

        major   = max(cnt0, cnt1)
        epsilon = major / total - 0.5       # 観測バイアス
        diff    = abs(epsilon - target_epsilon)

        print(f"{candidate=}, cnt0={cnt0}, cnt1={cnt1}, ε={epsilon:.5f}, diff={diff:.5f}")

        # 過去の best_diff よりも小さければ更新
        if diff < best_diff:
            best_diff      = diff
            best_epsilon   = epsilon
            best_candidate = candidate
            

    
    # 最も偏りが大きかった候補 k2 に対する recovered_bit を計算
    # この recovered_bit は、近似parity式の結果であり、
    # 直接的な鍵ビットそのものではないことに注意
    # 復号側で推定すべきビット
    cnt0, cnt1      = stats[best_candidate]
    recovered_bit   = 0 if cnt0 > cnt1 else 1

    return best_candidate, recovered_bit, stats, best_epsilon


# --- 動作確認用のサンプルコード ---
if __name__ == "__main__":
    # 乱数（または固定値）で秘密鍵を設定（各鍵は 4 ビット）
    secret_keys = (
        random.randint(0, 15),
        random.randint(0, 15),
        random.randint(0, 15)
       
    )
    
    # N 個の既知平文・暗号文ペアを生成する
    N = 1000 # 必要なペア数は偏りの大きさに依存
    plaintexts = []
    ciphertexts = []
    for _ in range(N):
        m = random.randint(0, 15)
        # m = _
        c = encrypt_cipherB(m, secret_keys)
        plaintexts.append(m)
        ciphertexts.append(c)

    # 線形攻撃の実行
    guessed_k2, recovered_bit, stats, epsilon = linear_attack(plaintexts, ciphertexts)
    print("\nGuessed k2:", hex(guessed_k2))
    print("Secret keys (k0, k1, k2):", secret_keys,'\n')
    print("Guessed k2 epsilon:", epsilon)
    print(f"Target epsilon: {target_epsilon:.5f}\n")
    print("Recovered bit (k0 ⊕ k1 ) ⋅ d:", recovered_bit)


    # 正しい (k0 ⊕ k1 ) ⋅ d の値を計算して比較
    true_key_xor = secret_keys[0] ^ secret_keys[1] 
    true_bit     = parity(true_key_xor, MASKD)
    print("Correct bit (k0 ⊕ k1) ⋅ d:", true_bit)