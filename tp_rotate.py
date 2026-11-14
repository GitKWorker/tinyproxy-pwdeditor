#!/usr/bin/env python3
"""Rotate the BasicAuth password of a tinyproxy account on remote routers.

The password is generated here and handed to the remote helper over the SSH
stdin channel, never as a command line argument, so it does not show up in a
process listing on either side. It is printed only after the remote helper has
confirmed the new password actually works.

Configuration lives outside this repository, at $TP_CONFIG or
/ql/data/config/tp-rotate.json. See config.example.json for the shape.

Usage:
    python3 tp_rotate.py            # rotate, then push to WeCom
    python3 tp_rotate.py --dry-run  # generate passwords, touch nothing
"""

import json
import os
import secrets
import subprocess
import sys
import urllib.request

# 0 O 1 l I are left out so a password read off a phone screen cannot be
# mistyped as its lookalike.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
DEFAULT_CONFIG = "/ql/data/config/tp-rotate.json"
PASSWORD_LENGTH = 8


def log(msg):
    print(msg, flush=True)


def gen_password(length=PASSWORD_LENGTH):
    """Generate a password with at least one upper, one lower and one digit."""
    while True:
        pw = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if (
            any(c.isupper() for c in pw)
            and any(c.islower() for c in pw)
            and any(c.isdigit() for c in pw)
        ):
            return pw


def ssh_rotate(target, password):
    """Push one password. Returns (ok, detail)."""
    label = target.get("label") or target.get("host", "?")
    key_path = target["key_path"]
    known_hosts = target.get("known_hosts") or os.path.join(
        os.path.dirname(key_path), "known_hosts." + label
    )
    cmd = [
        "ssh",
        "-T",
        "-i", key_path,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + known_hosts,
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
        "-p", str(target.get("port", 22)),
        "%s@%s" % (target["user"], target["host"]),
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=password + "\n",
            text=True,
            capture_output=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        return False, "ssh-timeout"
    except FileNotFoundError:
        return False, "ssh-not-installed"

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode == 0 and out.startswith("OK "):
        return True, out
    return False, out or err or "exit-%d" % proc.returncode


def wecom_send(key, content):
    url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + key
    body = json.dumps(
        {"msgtype": "text", "text": {"content": content}}
    ).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("errcode") == 0, data


def load_config():
    path = os.environ.get("TP_CONFIG", DEFAULT_CONFIG)
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, "config missing: %s" % path
    except ValueError as exc:
        return None, "config invalid: %s" % exc


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-n", "--dry-run"):
        os.environ["DRY_RUN"] = "1"
    dry = os.environ.get("DRY_RUN", "").strip().lower() in ("1", "true", "yes")

    cfg, err = load_config()
    if err:
        log(err)
        return 2

    targets = cfg.get("targets") or []
    if not targets:
        log("config has no targets")
        return 2

    lines = ["【tinyproxy 密码轮换】" + ("（DRY_RUN）" if dry else "")]
    failures = 0

    for target in targets:
        label = target.get("label") or target.get("host", "?")
        account = target.get("account", "user")
        password = gen_password()

        if dry:
            log(
                "[DRY_RUN] %s -> %s@%s:%s account=%s"
                % (
                    label,
                    target["user"],
                    target["host"],
                    target.get("port", 22),
                    account,
                )
            )
            lines.append("* %s  %s / %s  (未下发)" % (label, account, password))
            continue

        ok, detail = ssh_rotate(target, password)
        if ok:
            log("[OK] %s  %s / %s" % (label, account, password))
            lines.append("%s  %s / %s" % (label, account, password))
        else:
            failures += 1
            log("[FAIL] %s  %s" % (label, detail))
            lines.append("%s  失败：%s（原密码保持不变）" % (label, detail))

    content = "\n".join(lines)

    if dry:
        log("DRY_RUN, nothing pushed")
        return 0

    key = os.environ.get("WECOM_WEBHOOK_KEY", "").strip()
    if not key:
        log("[WECOM] WECOM_WEBHOOK_KEY not set, push skipped")
    else:
        try:
            sent, data = wecom_send(key, content)
            log("[WECOM] ok" if sent else "[WECOM] rejected: %s" % data)
        except Exception as exc:  # network errors must not hide the result
            log("[WECOM] error: %s" % exc)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
