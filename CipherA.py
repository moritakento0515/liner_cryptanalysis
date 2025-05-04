import random

# 定義した S-Box とその逆写像
S_BOX = {
    0x0: 0xF, 0x1: 0xE, 0x2: 0xB, 0x3: 0xC,
    0x4: 0x6, 0x5: 0xD, 0x6: 0x7, 0x7: 0x8,
    0x8: 0x0, 0x9: 0x3, 0xA: 0x9, 0xB: 0xA,
    0xC: 0x4, 0xD: 0x2, 0xE: 0x1, 0xF: 0x5,
}
INV_S_BOX = {v: k for k, v in S_BOX.items()}

# 線形マスク
ALPHA = 0b1001  # (1,0,0,1)
BETA  = 0b0010  # (0,0,1,0)

def parity(mask: int, x: int) -> int:
    """
    mask · x をビット単位で計算し、結果を mod 2 で返す。
    """
    return bin(mask & x).count("1") % 2

def encrypt_block(m: int, key: int) -> int:
    """
    4ビット平文 m と 8ビット鍵 key で 1ブロック暗号化を行う。
    key の上位4ビットを k0、下位4ビットを k1 とする。
    """
    k0 = (key >> 4) & 0xF
    k1 = key & 0xF
    u = m ^ k0
    v = S_BOX[u]
    c = v ^ k1
    return c

def decrypt_block(c: int, key: int) -> int:
    """
    4ビット暗号文 c と 8ビット鍵 key で 1ブロック復号を行う。
    """
    k0 = (key >> 4) & 0xF
    k1 = key & 0xF
    v = c ^ k1
    u = INV_S_BOX[v]
    m = u ^ k0
    return m

def linear_attack(pairs: list[tuple[int,int]]) -> tuple[int,list[int],list[int]]:
    """
    線形暗号解析を実行。
    与えられた (平文, 暗号文) ペア群から
      s = (α·k0)⊕(β·k1)
    を推定し、それを満たす鍵候補を返す。
    """
    N = len(pairs)
    T = [0, 0]
    for m, c in pairs:
        # 左辺 = (α·m) ⊕ (β·c) ⊕ 1
        lhs = (parity(ALPHA, m) ^ parity(BETA, c) ^ 1)
        T[lhs] += 1

    # T[0] > T[1] なら s=0, そうでなければ s=1
    s = 0 if T[0] > T[1] else 1

    # s を満たす鍵を全探索で絞り込む
    candidates = []
    for key in range(256):
        k0 = (key >> 4) & 0xF
        k1 = key & 0xF
        if (parity(ALPHA, k0) ^ parity(BETA, k1)) == s:
            candidates.append(key)

    return s, T, candidates

if __name__ == "__main__":
    # ランダム鍵の生成
    true_key = random.randint(0, 255)
    #true_key = 0xF3
    
    # 既知平文-暗号文ペアを N 個生成
    # N = 256
    # plaintexts = [random.randint(0, 15) for _ in range(N)]
    # pairs = [(m, encrypt_block(m, true_key)) for m in plaintexts]
    # 0から15までの16通りの平文を生成し、暗号文とのペアを作成
    plaintexts = list(range(16))
    pairs = [(m, encrypt_block(m, true_key)) for m in plaintexts]


    # 線形攻撃を実行
    s, T, candidates = linear_attack(pairs)

    print(f"True key: 0x{true_key:02X}")
    print(f"Estimated s: {s}")
    print(f"T0={T[0]}, T1={T[1]}")
    print(f"Candidates after filter: {len(candidates)} keys")

    # 候補群からさらに検証して正鍵を復元
    recovered = None
    for key in candidates:
        if all(encrypt_block(m, key) == c for m, c in pairs[:10]):
            recovered = key
            break

    if recovered is not None:
        print(f"Recovered key: 0x{recovered:02X}")
    else:
        print("Key not found in candidates.")
