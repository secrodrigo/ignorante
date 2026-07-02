```text
   _                               _        
  (_) __ _ _ _  ___  _ _ __ _ _ _ | |_  ___ 
  | |/ _` | ' \/ _ \| '_/ _` | ' \|  _|/ -_)
  |_|\__, |_||_\___/|_| \__,_|_||_|\__|\___|
     |___/                                  
```

utility tool :)

a small, dependency-free helper for ctf / hack the box workflows. one file,
stdlib only, lowercase aesthetic.

### modules

[>] `rs`    — reverse-shell listener with auto tty upgrade + recon

[>] `gen`   — reverse-shell one-liner generator (bash / nc / python / php / …)

[>] `serve` — quick http server for file transfer (download + upload)

[>] `scan`  — fast concurrent tcp connect scan + service/banner detection

[>] `enc` / `dec` — encoding toolbox (base64/32, hex, url, rot13, ascii85, auto)

### about

this is a utility tool for ctf, mostly used on htb. i update it as i find things
worth automating to make the process faster. it targets the boxes you are
authorized to attack (lab / ctf machines) — nothing here tries to hide from or
defeat defensive tooling.

### usage

```bash
# catch a shell (auto-detects python, upgrades to a pty, runs recon)
python3 ignorante.py rs 9001

# generate a reverse-shell one-liner (lhost auto-detected, prefers tun0)
python3 ignorante.py gen 9001                 # all payload types
python3 ignorante.py gen 10.10.14.5 9001 bash # one type, explicit lhost
python3 ignorante.py gen 9001 python3 -q      # quiet: payload only, pipeable

# serve the current dir over http (get to download, put to receive uploads)
python3 ignorante.py serve 8000 .

# scan a host (default common ports; -p 1-1000 / -p 22,80,443 / -p- for all)
python3 ignorante.py scan 10.10.10.10
python3 ignorante.py scan target.htb -p- -t 0.5 -w 800

# encode / decode (reads stdin if no data; 'auto' tries every scheme)
python3 ignorante.py enc b64 "secret"
python3 ignorante.py dec auto "ZmxhZ3tleWV9"
echo -n data | python3 ignorante.py enc hex -q
```

### flags

- `-q` / `--quiet` — no banner, no colors, decoration to stderr and data to
  stdout, so output pipes cleanly into other tools.

### technical

- **rs / listener:** raw tcp socket catches the connection, probes for
  python(3) and spawns a remote pty. when your stdin is a real terminal it drops
  into a raw passthrough so arrow keys, tab and ctrl-c reach the remote shell
  (ctrl-] to quit); otherwise it falls back to a line loop. sends the terminal
  size to the remote for clean redraws.
- **gen:** templated one-liners for common interpreters. auto-detects your
  attacker ip (prefers `tun0` for htb), or takes an explicit lhost.
- **serve:** stdlib http server. `GET` to pull files onto the target, `PUT`
  (`curl -T`) to exfil back. skips reverse-dns on bind so it starts instantly on
  isolated vpn subnets.
- **scan:** threaded tcp connect scan (`ThreadPoolExecutor`). grabs banners,
  does tls-aware handshakes for https ports, infers the service from the banner
  (falling back to the port map), and prints a suggested `nmap -sVC` follow-up.
  not a full nmap replacement — no root syn scan, os detection or nse.
- **enc / dec:** base64, base32, hex, url, rot13, ascii85. `dec auto` byte-scores
  every distinctive-alphabet decoder and shows the ones that yield readable text.

### roadmap

candidate modules: `cheat` (offline gtfobins-style lookup), `hashid` (hash type
id).
```
