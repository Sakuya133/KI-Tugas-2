import secrets

BLOCK = 16
ROUNDS = 10


def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _build_sboxes():
    inverse = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inverse[a] = b
                break
    sbox = []
    for a in range(256):
        x = inverse[a]
        value = x
        for shift in range(1, 5):
            value ^= ((x << shift) | (x >> (8 - shift))) & 0xFF
        sbox.append(value ^ 0x63)
    inv_sbox = [0] * 256
    for index, value in enumerate(sbox):
        inv_sbox[value] = index
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sboxes()


def _expand_key(key):
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 4 * (ROUNDS + 1)):
        word = list(words[i - 1])
        if i % 4 == 0:
            word = word[1:] + word[:1]
            word = [SBOX[b] for b in word]
            word[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([a ^ b for a, b in zip(words[i - 4], word)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(ROUNDS + 1)]


def _add_round_key(state, round_key):
    return [a ^ b for a, b in zip(state, round_key)]


def _sub_bytes(state, box):
    return [box[b] for b in state]


def _shift_rows(state):
    return [state[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]


def _inv_shift_rows(state):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[4 * ((c + r) % 4) + r] = state[4 * c + r]
    return out


def _mix_columns(state, matrix):
    out = []
    for c in range(4):
        col = state[4 * c:4 * c + 4]
        for row in matrix:
            value = 0
            for coef, byte in zip(row, col):
                value ^= _gmul(coef, byte)
            out.append(value)
    return out


MIX = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
INV_MIX = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def _encrypt_block(block, round_keys):
    state = _add_round_key(list(block), round_keys[0])
    for r in range(1, ROUNDS):
        state = _sub_bytes(state, SBOX)
        state = _shift_rows(state)
        state = _mix_columns(state, MIX)
        state = _add_round_key(state, round_keys[r])
    state = _sub_bytes(state, SBOX)
    state = _shift_rows(state)
    return bytes(_add_round_key(state, round_keys[ROUNDS]))


def _decrypt_block(block, round_keys):
    state = _add_round_key(list(block), round_keys[ROUNDS])
    for r in range(ROUNDS - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _sub_bytes(state, INV_SBOX)
        state = _add_round_key(state, round_keys[r])
        state = _mix_columns(state, INV_MIX)
    state = _inv_shift_rows(state)
    state = _sub_bytes(state, INV_SBOX)
    return bytes(_add_round_key(state, round_keys[0]))


def _pad(data):
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n


def _unpad(data):
    if not data or len(data) % BLOCK:
        raise ValueError("Panjang data tidak valid.")
    n = data[-1]
    if not 1 <= n <= BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid.")
    return data[:-n]


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) != 16:
        raise ValueError("Key harus 16 byte.")
    return _expand_key(bytes(key))


def _check_iv(iv):
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != BLOCK:
        raise ValueError("IV harus 16 byte.")
    return bytes(iv)


def cbc_encrypt(data, key, iv):
    round_keys = _check_key(key)
    previous = _check_iv(iv)
    if len(data) % BLOCK:
        raise ValueError("Panjang data harus kelipatan 16.")
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        mixed = bytes(a ^ b for a, b in zip(data[i:i + BLOCK], previous))
        previous = _encrypt_block(mixed, round_keys)
        out.extend(previous)
    return bytes(out)


def cbc_decrypt(data, key, iv):
    round_keys = _check_key(key)
    previous = _check_iv(iv)
    if len(data) % BLOCK:
        raise ValueError("Panjang data harus kelipatan 16.")
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        block = data[i:i + BLOCK]
        plain = _decrypt_block(block, round_keys)
        out.extend(a ^ b for a, b in zip(plain, previous))
        previous = block
    return bytes(out)


def ensure_available():
    if SBOX[0] != 0x63 or INV_SBOX[0x63] != 0:
        raise NotImplementedError("S-box AES tidak valid.")


def encrypt_message(plaintext, key):
    iv = secrets.token_bytes(BLOCK)
    return iv, cbc_encrypt(_pad(bytes(plaintext)), key, iv)


def decrypt_message(iv, ciphertext, key):
    return _unpad(cbc_decrypt(bytes(ciphertext), key, iv))