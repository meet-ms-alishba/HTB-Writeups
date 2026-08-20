Category: Crypto / Reverse Engineering Difficulty: Medium Key Techniques: UPX unpacking, static analysis (objdump), FNV-1a hash reversing, XOR key derivation, Hill cipher cryptanalysis

Overview

The challenge ships a custom "ransomware-style" encryptor binary along with an encrypted file. The goal is to reverse the binary's key-derivation and encryption logic well enough to write a standalone decryptor and recover the flag — without ever needing to run the original binary against the target file.

Step 1 — Initial Recon

Running file on the binary showed a stripped, statically-linked-looking ELF with no section headers, which immediately broke standard tools like objdump -d (it had nothing to disassemble against). Program headers via readelf -lW also showed both LOAD segments pointing at file offset 0x0, a telltale sign the header info had been mangled — not by hand, but because the binary was packed.

$ file ransom
ransom: ELF 64-bit LSB pie executable, x86-64 ... statically linked, no section header
Step 2 — Unpacking

strings on the binary surfaced the giveaway: UPX! markers buried in the packed stub. Installed upx-ucl and unpacked directly:

$ upx -d ransom -o ransom_unpacked
File size         Ratio      Format
19835 <-  8996   45.35%   linux/amd64

This produced a normal dynamically-linked ELF with a proper interpreter and workable section layout — from here on, standard objdump -d -M intel worked fine.

Step 3 — Mapping the Functions

With symbols stripped but PLT stubs intact, the call graph was reconstructed manually by following call targets into libc functions:

read_file() — fopen → fseek/ftell (get size) → malloc → fread, standard "load whole file into memory" helper.
write_file() — fopen → fwrite, output helper.
Main encryption routine — calls read_file(), builds a header (DWORD 0x52414e53 = ASCII "SNAR" magic), calls time() for the timestamp, hands off to the actual crypto core, then writes a 20-byte header + ciphertext to <name>.enc via sprintf("%s.enc", ...).

Header layout confirmed as: 4s magic + Q timestamp + I file size + 4 bytes padding = 20 bytes, matching what the challenge's own seed.py printed (Magic: SNAR, Timestamp, File Size).

Step 4 — The Crypto Core

Disassembling the core function revealed an FNV-1a 64-bit hash of the timestamp, immediately recognizable from the constant 0x100000001b3 (FNV prime) and offset basis 0xcbf29ce484222325, XORed at the end with 0xDEADBEEFCAFEBABE.

This hash feeds two sub-routines:

An XOR key generator (8 bytes).
A 2×2 matrix generator (Hill cipher key), derived from the hash through a chain of LCG-style multiply-add steps, with a fallback branch to guarantee the matrix determinant is odd (invertible mod 256).

Critically, tracing the actual encryption order in the core function showed:

plaintext --> Hill cipher transform --> XOR with key --> ciphertext

So decryption must undo the XOR first, then apply the modular inverse Hill matrix.

Step 5 — The Bug That Cost 3 Days

The first reversing pass (via decompiler output) produced this for the XOR key:

python
xor_key = [(h_ts >> ((i * 11) & 0x3F)) & 0xFF for i in range(8)]

Every subsequent decrypt attempt produced garbage — despite the Hill matrix inverse math checking out. Going back to the raw disassembly of the key-derivation loop settled it:

asm
lea ecx, [rax*8+0]      ; cl = i * 8   -- NOT i * 11
mov r10, rdi             ; r10 = hash
shr r10, cl
mov BYTE [rdx+rax], r10b

The decompiler-assisted read had misattributed the shift amount. The real logic is a plain byte-split of the 64-bit hash:

python
xor_key = [(h_ts >> (i * 8)) & 0xFF for i in range(8)]

One wrong shift constant — that was the entire blocker. Lesson: when decompiler output and runtime behavior disagree, trust the raw disassembly over the cleaned-up pseudocode.

Step 6 — Final Decryption Script
python
import struct

def modInverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def fnv1a_64(val):
    h = 0xCBF29CE484222325
    for i in range(8):
        byte = (val >> (i * 8)) & 0xFF
        h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h ^ 0xDEADBEEFCAFEBABE

def derive_keys(timestamp):
    h_ts = fnv1a_64(timestamp)
    xor_key = [(h_ts >> (i * 8)) & 0xFF for i in range(8)]

    lVar2 = (h_ts * 0x5851F42D4C957F2D + 0x6C576FAC43FD007C) & 0xFFFFFFFFFFFFFFFF
    uVar4 = lVar2 & 0xFFFFFFFF
    uVar1 = (uVar4 * 0x4C957F2D + 0xF767814F) & 0xFFFFFFFF
    uVar3 = uVar1 & 0xFF
    uVar4 = (uVar4 & 0xFF) | 1
    uVar1 = (uVar1 * 0x4C957F2D + 0xF767814F) & 0xFFFFFFFF
    uVar5 = uVar1 & 0xFF
    uVar1 = (((uVar1 * 0x4C957F2D + 0xF767814F) & 0xFFFFFFFF) & 0xFF) | 1
    a, b, c, d = uVar4, uVar3, uVar5, uVar1
    if ((uVar4 * uVar1 - uVar3 * uVar5) & 1) == 0:
        a = ((lVar2 & 0xFF) | 1) + 2
    return xor_key, [a, b, c, d]

with open("secret.txt.enc", "rb") as f:
    header = f.read(20)
    ciphertext = bytearray(f.read())

magic, timestamp, file_size = struct.unpack("<4sQI4x", header)
xor_key, matrix = derive_keys(timestamp)
a, b, c, d = matrix

det = (a * d - b * c) % 256
det_inv = modInverse(det, 256)
inv_a = (d * det_inv) % 256
inv_b = (-b * det_inv) % 256
inv_c = (-c * det_inv) % 256
inv_d = (a * det_inv) % 256

buf = bytearray(ciphertext)
for i in range(len(buf)):
    buf[i] ^= xor_key[i % 8]

plaintext = bytearray()
for i in range(0, len(buf), 2):
    if i + 1 < len(buf):
        c1, c2 = buf[i], buf[i + 1]
        p1 = (inv_a * c1 + inv_b * c2) % 256
        p2 = (inv_c * c1 + inv_d * c2) % 256
        plaintext.append(p1)
        plaintext.append(p2)

print(plaintext[:file_size].decode("utf-8", errors="ignore"))
Flag
HTB{...}
