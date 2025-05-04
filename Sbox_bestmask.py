# S-Box 定義
S_BOX = {
    0x0: 0xF, 0x1: 0xE, 0x2: 0xB, 0x3: 0xC,
    0x4: 0x6, 0x5: 0xD, 0x6: 0x7, 0x7: 0x8,
    0x8: 0x0, 0x9: 0x3, 0xA: 0x9, 0xB: 0xA,
    0xC: 0x4, 0xD: 0x2, 0xE: 0x1, 0xF: 0x5,
}

def bit_dot(mask: int, x: int) -> int:
    """
    mask · x mod 2 を計算（GF(2) のスカラー積）
    """
    return bin(mask & x).count("1") % 2

def find_best_masks():
    results = []
    # α, β を 1～15 (非ゼロ 4ビット) の全組み合わせで試す
    for alpha in range(1, 16):
        for beta in range(1, 16):
            match_count = 0
            # S-Box の全入力 x について α·x == β·S[x] の回数をカウント
            for x in range(16):
                if bit_dot(alpha, x) == bit_dot(beta, S_BOX[x]):
                    match_count += 1
            p = match_count / 16.0
            bias = abs(p - 0.5)
            results.append((bias, alpha, beta, match_count, p))

    # バイアスの大きい順 (= 情報量の多い順) にソート
    results.sort(reverse=True, key=lambda t: t[0])

    # 上位10件を返す
    return results[:10]

if __name__ == "__main__":
    top10 = find_best_masks()
    print("バイアス順 上位10マスク組み合わせ")
    print("バイアス   α(10進) α(2進)   β(10進) β(2進)   一致回数  確率 p")
    for bias, alpha, beta, cnt, p in top10:
        print(f"{bias:>6.3f}   "
              f"{alpha:>2d}({alpha:04b})   "
              f"{beta:>2d}({beta:04b})   "
              f"{cnt:>2d}/{16:>2d}   {p:.3f}")