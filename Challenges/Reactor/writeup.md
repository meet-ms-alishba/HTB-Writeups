**Category:** Web / Node.js

---

##  User Access
1. **Enumeration:** Enumerated the application and discovered an exposed, web-accessible database dump.
2. **Credential Extraction:** Downloaded the database dump and extracted the password hash for the user `engineer@htb`.
3. **Cracking:** Cracked the extracted hash offline to recover the plaintext password.
4. **Foothold:** Used the cracked credentials to log in via SSH/Shell as `engineer` and successfully retrieved `user.txt`.

---

##  Privilege Escalation (root)
1. **Vulnerability Identification:** Identified that the Node.js version in use was vulnerable to **CVE-2025-55182** (React Server Components "Flight" protocol deserialization RCE).
2. **Web RCE:** Exploited this vulnerability to achieve Remote Code Execution (RCE) as the low-privileged web service user.
3. **Local Enumeration:** Ran a local port scan for loopback-only listeners (`netstat`/`ss -tlnv` style check) and found a service running on `127.0.0.1:9229`. This is the default **Node.js Inspector/debugger protocol port**.
4. **Pivoting:** Since the port was bound to loopback only and unreachable from the outside, used **SSH local port forwarding** to map the remote port `127.0.0.1:9229` to a local port on the Kali Linux machine.
5. **Exploitation:** Connected to the now-reachable Node Inspector protocol and used `execSync()` via the debugger interface to inject a command, adding root's identity and spawning a shell.
6. **Root Capture:** Broke out of the debugger session (`Ctrl+C`) back to the injected shell, then executed `bash -p` to stabilize and secure full root privileges.

---

##  Key Techniques Used
*   Database credential extraction & offline hash cracking
*   CVE-2025-55182 (Next.js/React Server Components RCE) exploitation
*   Loopback service discovery via local port enumeration
*   SSH local port forwarding (Tunneling) to bypass network restrictions
*   Node.js Inspector protocol abuse via `execSync` injection for privilege escalation

---

##  Lessons for Real-World DB/Infra Security
*   **Secure Backups:** Database dumps and backups must never be stored in web-accessible directories.
*   **Strong Hashing:** Password hashes require strong, modern algorithms (like `bcrypt` or `argon2`) along with proper salting to prevent offline cracking after a leak.
*   **Patch Management:** Framework versions must be updated and patched promptly; old versions (like the one vulnerable to CVE-2025-55182) provide an easy initial foothold.
*   **Disable Debugging in Production:** Debug/inspector ports (such as Node's `9229`) should never be enabled in production environments. Even if bound to loopback, an attacker with local code execution can reach them via tunneling.
*   **Least Privilege:** The initial RCE foothold should not have an open path to root-equivalent access through an unauthenticated local debugger.

---

##  Reflections
> First HTB machine solved end-to-end! It was a great mix of modern web exploitation (recent CVE) and classic privilege escalation (spotting an internally-bound debug service and pivoting via tunneling). This box serves as an excellent reminder that even after getting initial code execution, checking what is listening locally on loopback-only services is often the fastest path to a full system compromise.
