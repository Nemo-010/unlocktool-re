"""The tool's own payload-encryption scheme, recovered from IL.

Recovered from ColokTool.exe `ColokTool.Loader_Thread::Encryption(uint8[], uint8[], bool)`:

    sha  = SHA256(password_bytes)
    prf  = Rfc2898DeriveBytes(sha, saltBytes, 1000)      // PBKDF2-HMAC-SHA1
    aes  = AesCryptoServiceProvider, KeySize 256, BlockSize 128, Mode CBC
    aes.Key = prf.GetBytes(32)
    aes.IV  = prf.GetBytes(16)      <-- same PBKDF2 instance continues

The two literals come from the `.cctor` of the same type, which loads them
from FieldRVA initialised arrays:

    saltBytes = 00 00 01 02 03 04 05 06 F1 F0 88 10 22 95   (14 bytes)
    key       = "RDAXTEAM2024"                              (12 bytes)

Note the argument name: the second parameter of `Encryption` is the *password*
that gets SHA-256'd, and the caller passes `Loader_Thread.key`, i.e. the ASCII
string.  So the PBKDF2 password is SHA256(b"RDAXTEAM2024"), not the string
itself.  The repository's OFFLINE-DATA-README.md omits that SHA-256 step.
"""

import hashlib

SALT = bytes.fromhex('0000010203040506f1f088102295')
PASSWORD_RDA = b'RDAXTEAM2024'
PASSWORD_RDA_SEC = b'RDAXTEAMSEC2025'
ITERATIONS = 1000
KEY_LEN = 32
IV_LEN = 16


def derive(password, salt=SALT, iterations=ITERATIONS):
    """Reproduce Rfc2898DeriveBytes(sha256(password), salt, iterations)."""
    hashed = hashlib.sha256(password).digest()
    dk = hashlib.pbkdf2_hmac('sha1', hashed, salt, iterations, KEY_LEN + IV_LEN)
    return dk[:KEY_LEN], dk[KEY_LEN:]


# --- a tiny pure-Python AES-256-CBC, so the reproduction has no dependencies --

_SBOX = None
_INV_SBOX = None


def _build_sbox():
    global _SBOX, _INV_SBOX
    if _SBOX is not None:
        return
    p = 1
    q = 1
    sbox = [0] * 256
    sbox[0] = 0x63
    while True:
        # multiply p by 3
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        # divide q by 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ \
            ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    _SBOX = sbox
    _INV_SBOX = inv


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _expand_key(key):
    _build_sbox()
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_round_key(state, w, rnd):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= w[rnd * 4 + c][r]


def _shift_rows(s):
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]


def _inv_shift_rows(s):
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]


def _mix_columns(s):
    for c in range(4):
        a = [s[r][c] for r in range(4)]
        s[0][c] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
        s[1][c] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
        s[2][c] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
        s[3][c] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _inv_mix_columns(s):
    for c in range(4):
        a = [s[r][c] for r in range(4)]
        s[0][c] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
        s[1][c] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
        s[2][c] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
        s[3][c] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)


def _to_state(block):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))


def aes_encrypt_block(key, block):
    w, nr = _expand_key(key)
    s = _to_state(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, nr):
        s = [[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, w, rnd)
    s = [[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
    _shift_rows(s)
    _add_round_key(s, w, nr)
    return _from_state(s)


def aes_decrypt_block(key, block):
    w, nr = _expand_key(key)
    s = _to_state(block)
    _add_round_key(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(s)
        s = [[_INV_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
        _add_round_key(s, w, rnd)
        _inv_mix_columns(s)
    _inv_shift_rows(s)
    s = [[_INV_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
    _add_round_key(s, w, 0)
    return _from_state(s)


def cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError('ciphertext length %d is not a multiple of 16' % len(data))
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        plain = aes_decrypt_block(key, block)
        out += bytes(a ^ b for a, b in zip(plain, prev))
        prev = block
    return bytes(out)


def cbc_encrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError('plaintext length %d is not a multiple of 16' % len(data))
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = aes_encrypt_block(key, block)
        out += prev
    return bytes(out)


# --- optional native accelerator -------------------------------------------
#
# The pure-Python AES above is correct but slow (~30 KiB/s).  For bulk
# verification of the shipped payloads we shell out to `openssl enc`, which is
# present on essentially every Linux/macOS box.  Both paths are exercised by
# tests/test_crypto.py, which asserts they agree byte-for-byte.

import shutil
import subprocess

_OPENSSL = shutil.which('openssl')


def openssl_available():
    return _OPENSSL is not None


def _openssl_cbc(key, iv, data, decrypt):
    args = [_OPENSSL, 'enc', '-aes-256-cbc', '-nopad',
            '-K', key.hex(), '-iv', iv.hex()]
    if decrypt:
        args.insert(2, '-d')
    proc = subprocess.run(args, input=data, capture_output=True)
    if proc.returncode != 0:
        raise ValueError('openssl failed: %s' % proc.stderr.decode('latin1'))
    return proc.stdout


def cbc_decrypt_fast(key, iv, data):
    if _OPENSSL:
        return _openssl_cbc(key, iv, data, True)
    return cbc_decrypt(key, iv, data)


def cbc_encrypt_fast(key, iv, data):
    if _OPENSSL:
        return _openssl_cbc(key, iv, data, False)
    return cbc_encrypt(key, iv, data)


def pkcs7_strip(data):
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def decrypt_programs_bin(data, password=PASSWORD_RDA, strip_padding=True,
                         fast=True):
    """Decrypt one `programs.bin` firehose loader."""
    key, iv = derive(password)
    decrypt = cbc_decrypt_fast if fast else cbc_decrypt
    plain = decrypt(key, iv, data)
    return pkcs7_strip(plain) if strip_padding else plain


def encrypt_programs_bin(data, password=PASSWORD_RDA, fast=True):
    key, iv = derive(password)
    encrypt = cbc_encrypt_fast if fast else cbc_encrypt
    return encrypt(key, iv, pkcs7_pad(data))


def is_elf(data):
    return data[:4] == b'\x7fELF'
