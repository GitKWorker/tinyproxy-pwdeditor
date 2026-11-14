#!/usr/bin/env python3
"""Rotate the BasicAuth password of a tinyproxy account on remote routers.

The password is generated here and handed to the remote helper over the SSH
stdin channel, never as a command line argument, so it does not show up in a
process listing on either side. It is printed only after the remote helper has
confirmed the new password actually works.

Configuration comes from the TINYPROXY_PWDEDITOR environment variable, one
variable holding every parameter:

    TINYPROXY_PWDEDITOR=label=router-a,host=10.0.0.1,port=22,user=root,account=user,key=/ql/data/keys/tp-router-a,hostkey=ssh-ed25519:AAAA...

Several routers are separated by "|". A JSON file is still accepted as a
fallback ($TP_CONFIG or /ql/data/config/tp-rotate.json) for older installs.

Usage:
    python3 tp_rotate.py            # rotate, then push to WeCom
    python3 tp_rotate.py --dry-run  # parse config, generate passwords, touch nothing
"""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import urllib.request

# 0 O 1 l I are left out so a password read off a phone screen cannot be
# mistyped as its lookalike.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
DEFAULT_CONFIG = "/ql/data/config/tp-rotate.json"
ENV_NAME = "TINYPROXY_PWDEDITOR"
PASSWORD_LENGTH = 8

FIELDS = ("label", "host", "port", "user", "account", "key", "known_hosts", "hostkey")


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


def parse_spec(spec):
    """Parse 'k=v,k=v|k=v' into a list of dicts.

    Deliberately restricted to characters that survive a shell assignment: no
    spaces, no quotes, no $ or backticks. That is why the host key is written
    as 'ssh-ed25519:AAAA...' instead of the usual space separated pair.
    """
    targets = []
    for chunk in spec.split("|"):
        chunk = chunk.strip()
        if not chunk:
            continue
        item = {}
        for pair in chunk.split(","):
            pair = pair.strip()
            if not pair:
                continue
            key, sep, value = pair.partition("=")
            if not sep:
                raise ValueError("field without '=': %r" % pair)
            key = key.strip()
            if key not in FIELDS:
                raise ValueError(
                    "unknown field %r, allowed: %s" % (key, ", ".join(FIELDS))
                )
            item[key] = value.strip()
        if not item:
            continue
        if "host" not in item:
            raise ValueError("missing required field: host")
        if "key" not in item:
            raise ValueError("missing required field: key (private key path)")
        targets.append(item)
    return targets


def load_targets():
    spec = os.environ.get(ENV_NAME, "").strip()
    if spec:
        try:
            return parse_spec(spec), None
        except ValueError as exc:
            return None, "%s malformed: %s" % (ENV_NAME, exc)

    # Fallback: JSON file, kept for installs that predate the env variable.
    path = os.environ.get("TP_CONFIG", DEFAULT_CONFIG)
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        return None, "neither %s nor the config file %s is present" % (ENV_NAME, path)
    except ValueError as exc:
        return None, "config file %s is not valid JSON: %s" % (path, exc)

    targets = []
    for raw in cfg.get("targets") or []:
        item = dict(raw)
        if "key_path" in item and "key" not in item:
            item["key"] = item.pop("key_path")
        targets.append(item)
    return targets, None


def prepare_known_hosts(target):
    """Return (path, is_temp) for the host key pin of this target.

    Three ways to pin the host key, in priority order:
      1. hostkey=ssh-ed25519:AAAA...  -> materialised into a temp file
      2. known_hosts=/path/to/file    -> used as is
      3. neither                      -> <private key dir>/known_hosts.<label>
    """
    host = target["host"]
    port = int(target.get("port", 22))
    hostfield = host if port == 22 else "[%s]:%d" % (host, port)

    hostkey = target.get("hostkey")
    if hostkey:
        keytype, sep, key = hostkey.partition(":")
        if not sep or not key or " " in hostkey:
            raise ValueError(
                "hostkey must be 'ssh-ed25519:AAAAC3...' "
                "(colon separated, no spaces)"
            )
        fd, path = tempfile.mkstemp(prefix="tp-kh-", suffix=".tmp")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("%s %s %s\n" % (hostfield, keytype, key))
        return path, True

    if target.get("known_hosts"):
        return target["known_hosts"], False

    label = target.get("label") or host
    return os.path.join(os.path.dirname(target["key"]), "known_hosts." + label), False


def ssh_rotate(target, password):
    """Push one password. Returns (ok, detail)."""
    try:
        kh_path, kh_temp = prepare_known_hosts(target)
    except ValueError as exc:
        return False, "config: %s" % exc

    cmd = [
        "ssh",
        "-T",
        "-i", target["key"],
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + kh_path,
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
        "-p", str(target.get("port", 22)),
        "%s@%s" % (target.get("user", "root"), target["host"]),
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
    finally:
        if kh_temp:
            try:
                os.unlink(kh_path)
            except OSError:
                pass

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


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-n", "--dry-run"):
        os.environ["DRY_RUN"] = "1"
    dry = os.environ.get("DRY_RUN", "").strip().lower() in ("1", "true", "yes")

    targets, err = load_targets()
    if err:
        log(err)
        return 2
    if not targets:
        log("no target configured")
        return 2

    lines = ["【tinyproxy 密码轮换】" + ("（DRY_RUN）" if dry else "")]
    failures = 0

    for target in targets:
        label = target.get("label") or target["host"]
        account = target.get("account", "user")

        if dry:
            try:
                kh_path, kh_temp = prepare_known_hosts(target)
                if kh_temp:
                    os.unlink(kh_path)
                kh_note = "inline hostkey" if target.get("hostkey") else kh_path
            except ValueError as exc:
                log("[CONFIG] %s  %s" % (label, exc))
                failures += 1
                continue
            log(
                "[DRY_RUN] %s -> %s@%s:%s account=%s key=%s kh=%s"
                % (
                    label,
                    target.get("user", "root"),
                    target["host"],
                    target.get("port", 22),
                    account,
                    target["key"],
                    kh_note,
                )
            )
            lines.append("* %s  %s / %s  (not pushed)" % (label, account, gen_password()))
            continue

        password = gen_password()
        ok, detail = ssh_rotate(target, password)
        if ok:
            log("[OK] %s  %s / %s" % (label, account, password))
            lines.append("%s  %s / %s" % (label, account, password))
        else:
            failures += 1
            log("[FAIL] %s  %s" % (label, detail))
            lines.append("%s  failed: %s (previous password kept)" % (label, detail))

    content = "\n".join(lines)

    if dry:
        log("DRY_RUN, nothing pushed")
        return 1 if failures else 0

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
