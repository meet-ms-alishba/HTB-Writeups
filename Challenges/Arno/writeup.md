# Arno — Mobile Challenge 

**Category:** Mobile / Reverse Engineering
**Platform:** Android (Unity IL2CPP)
**Goal:** Recover the hidden flag from `Arno.apk`
**Tools:** `unzip`, jadx-gui, Il2CppDumper, Python (`pycryptodome`)

---

## 1. TL;DR

The APK is a Unity game built with **IL2CPP**. The flag is AES-encrypted, but the **key, IV and ciphertext are all shipped inside the app** as static byte arrays stored in `global-metadata.dat`. Reading those bytes at the right offsets and decrypting them with AES-256-CBC reveals the flag.

**Root cause:** hardcoded cryptographic material (client-side secrets).

---

## 2. Recon

Unzip the APK and look at the structure:

```bash
unzip -o Arno.apk -d apk
ls apk apk/lib/* apk/assets/bin/Data
```

Observations (also visible in jadx-gui):

- `lib/arm64-v8a/` only, so native code is arm64.
- `assets/bin/Data/` with `data.unity3d`, `boot.config`, `ScriptingAssemblies.json`, which means a **Unity** app.
- No managed `Assembly-CSharp.dll` to decompile, so the game logic is compiled to native code (**IL2CPP**).

> Running `dotnet` on the game code does not work here, because IL2CPP converts C# to C++ and ships it as `libil2cpp.so`.

---

## 3. Dumping the IL2CPP metadata

IL2CPP keeps type and method names in `global-metadata.dat`. **Il2CppDumper** takes `libil2cpp.so` + `global-metadata.dat` and produces `dump.cs` (class, field and method signatures, no method bodies).

```bash
./Il2CppDumper libil2cpp.so global-metadata.dat out/
```

---

## 4. Finding the interesting class

`dump.cs` is large (~21 MB), but game code lives only in the `Assembly-CSharp.dll` image. Searching for its `TypeDefIndex` range reveals a single custom class:

```csharp
public class FlagControl : MonoBehaviour
{
    public GameObject textField;
    public List<string> quotes;

    public void PopulateQuotes();
    public void ShowQuote();
    public byte[] GetKey();
    public byte[] GetIV();
    public byte[] GetFlag();
    public string DecryptFlag(byte[] key, byte[] iv, byte[] encryptedData);
}
```

`GetKey` / `GetIV` / `GetFlag` / `DecryptFlag` strongly suggest symmetric encryption of the flag.

---

## 5. Locating the data

Right after it, the compiler-generated `<PrivateImplementationDetails>` class holds static byte arrays, with their **metadata offsets** in the dump:

| Array size | Metadata offset | Interpretation |
|---|---|---|
| 32 bytes | `0x3EBAB0` | AES-256 key |
| 16 bytes | `0x3EBA48` | IV |
| 48 bytes | `0x3EBA78` | Ciphertext (3 AES blocks) |
| 38 / 17 bytes | `0x3EBA20` / `0x3EBA60` | Other data (quotes/decoys) |

The sizes match **AES-256-CBC** exactly: 32-byte key, 16-byte IV, ciphertext a multiple of 16.

---

## 6. Solution

Read the bytes directly from `global-metadata.dat` and decrypt:

```python
#!/usr/bin/env python3
import sys, zipfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

apk = sys.argv[1]
MAGIC = bytes.fromhex("AF1BB1FA")          # IL2CPP metadata header
KEY_OFF, IV_OFF, CT_OFF = 0x3EBAB0, 0x3EBA48, 0x3EBA78

z = zipfile.ZipFile(apk)
for name in z.namelist():
    d = z.read(name)
    base = d.find(MAGIC)
    if base != -1:
        break

key = d[base+KEY_OFF : base+KEY_OFF+32]
iv  = d[base+IV_OFF  : base+IV_OFF+16]
ct  = d[base+CT_OFF  : base+CT_OFF+48]

pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
print(unpad(pt, 16).decode())
```

```bash
pip install pycryptodome --break-system-packages
python3 solve.py Arno.apk
```

**Flag:** `HTB{REDACTED}`

---

## 7. Mistakes and dead ends

- Tried to treat the dumped `.dll` as a normal .NET assembly. It is IL2CPP, so `dotnet` / dnSpy do not apply.
- First script failed with `FileNotFoundError` because the APK path was relative to the wrong directory.
- The metadata file was not at the expected `Managed/Metadata/` path. Scanning for the magic header `AF 1B B1 FA` made the script independent of file location.

---

## 8. Vulnerability and mitigation

| | |
|---|---|
| **Issue** | Hardcoded cryptographic key / IV alongside the ciphertext |
| **CWE** | CWE-321 (Hardcoded Cryptographic Key), CWE-798 (Hardcoded Credentials) |
| **OWASP Mobile** | M10: Insufficient Cryptography |
| **Impact** | Anyone with the APK can recover the protected secret offline |
| **Fix** | Do not ship secrets in the client. Keep them server-side, or use Android Keystore for device-bound keys |

---

## 9. Takeaways

1. Identify the app type first (native Java, Unity Mono, Unity IL2CPP, Flutter...). It decides your toolchain.
2. IL2CPP hides code, not data. Static arrays remain recoverable from the metadata.
3. Field sizes in `dump.cs` (32 / 16 / 48) can reveal the crypto scheme without reading any code.
4. Writing a path-independent script (magic-byte search) saves time when the file layout differs.
