Category: Web / Node.js

User Access
Enumerated the app and found a database dump exposed/accessible.
Dumped the database and extracted a password hash for user engineer@htb.
Cracked the hash offline to recover the plaintext password.
Used the credentials to gain shell access as engineer, retrieving user.txt.
Privilege Escalation (root)
Identified the Node.js version in use was vulnerable to CVE-2025-55182 (React Server Components "Flight" protocol deserialization RCE).
Exploited it to get RCE as the low-priv web service user.
From that foothold, ran a port-scan for loopback-only listeners (netstat/ss -tlnv style check) and found something interesting running on 127.0.0.1:9229 -- the default Node.js Inspector/debugger protocol port.
Since it was bound to loopback only, it wasn't reachable directly from outside -- used SSH local port forwarding to map the remote 127.0.0.1:9229 to a local port on the Kali machine.
With the Node Inspector protocol now reachable, used execSync() via the debugger interface to inject a command adding root's identity / spawning a shell.
Broke out via Ctrl+C from the debugger session back to the injected shell, ran bash -p to stabilize with root privileges.
Key Techniques Used
Database credential extraction + offline hash cracking
CVE-2025-55182 (Next.js/React Server Components RCE)
Loopback service discovery via local port enumeration
SSH local port forwarding to reach an internally-bound service
Node.js Inspector protocol abuse (execSync injection) for privesc
Lessons for real-world DB/infra security
Database dumps/backups should never be web-accessible
Password hashes need strong algorithms (bcrypt/argon2) + salting -- weak hashes are crackable offline once leaked
Framework versions must be patched promptly (CVE-2025-55182 was the initial foothold)
Debug/inspector ports (like Node's 9229) should never be left enabled in production, even on loopback -- if an attacker gets any code execution, loopback-bound services become reachable via tunneling
Principle of least privilege: the initial RCE foothold should not have had a path to root-equivalent access via a debugger left open
Reflections

First HTB machine solved end-to-end -- a good mix of web (recent CVE exploitation) and classic privesc (spotting an internally-bound debug service and pivoting to it via tunneling). A good reminder that even after getting code execution, checking what's listening locally (loopback-only services) is often the fastest path to full compromise.
