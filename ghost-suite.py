#!/usr/bin/env python3

import os, sys, time, threading, socket, hashlib, base64, random, string, subprocess, re, json, math, struct, platform, webbrowser, getpass
from pathlib import Path
from collections import Counter

# ---------------- optional libs ----------------
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    class _C:
        RED=GREEN=YELLOW=CYAN=MAGENTA=BLUE=WHITE=RESET=""
    class _S:
        BRIGHT=NORMAL=RESET_ALL=""
    Fore=_C(); Style=_S()

# Capstone optional
HAS_CAPSTONE = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    HAS_CAPSTONE = True
except Exception:
    HAS_CAPSTONE = False

# ---------------- WhatsApp follow gate ----------------
WHATSAPP_CHANNEL = "https://whatsapp.com/channel/0029Vb6KGax2f3EQhTC9G43o"
MARKER_PATH = Path.home() / ".ghostsuite_followed"

def clear():
    try:
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")
    except:
        pass

def hr(c=Fore.GREEN):
    print(c + "-"*72 + Style.RESET_ALL)

def info(m): print(Fore.CYAN + "[i] " + m + Style.RESET_ALL)
def ok(m):   print(Fore.GREEN + "[+] " + m + Style.RESET_ALL)
def warn(m): print(Fore.YELLOW + "[!] " + m + Style.RESET_ALL)
def err(m):  print(Fore.RED + "[x] " + m + Style.RESET_ALL)
def pause(): input(Fore.YELLOW + "\n[Press Enter to continue]" + Style.RESET_ALL)

def require_whatsapp_follow(force=False):
    """
    First-run gate: open WhatsApp channel and ask user to confirm.
    Writes MARKER_PATH in user's home to skip next runs.
    """
    if MARKER_PATH.exists() and not force:
        return
    clear()
    print("="*72)
    print("  👻 GhostSuite — First time setup")
    print("="*72)
    print()
    print("Before using GhostSuite, please visit and follow our WhatsApp channel:")
    print()
    print(Fore.GREEN + "  " + WHATSAPP_CHANNEL + Style.RESET_ALL)
    print()
    print("Opening your default browser now...")
    try:
        webbrowser.open(WHATSAPP_CHANNEL)
    except Exception:
        pass
    try:
        info(f"Platform: {platform.system()}  User: {getpass.getuser()}")
    except Exception:
        pass
    resp = input("\nAfter following, type 'followed' (or press Enter). Type 'skip' to exit: ").strip().lower()
    if resp == "skip":
        err("Follow requirement not satisfied — exiting.")
        sys.exit(1)
    try:
        MARKER_PATH.write_text(f"confirmed by {getpass.getuser()} on {time.asctime()}\n")
        ok("Confirmation saved. Starting toolkit...")
    except Exception as e:
        warn(f"Couldn't write marker: {e} — continuing this run.")
    time.sleep(1)
    clear()

# ---------------- small helpers ----------------
def is_windows(): return os.name == "nt"
def is_posix(): return os.name == "posix"
def in_termux(): return Path("/data/data/com.termux").exists() or ("TERMUX" in os.environ)

def shutil_which(cmd):
    try:
        from shutil import which
        return which(cmd)
    except:
        return None

def _entropy(b:bytes):
    if not b: return 0.0
    freq=[0]*256
    for c in b: freq[c]+=1
    ent=0.0; n=len(b)
    for f in freq:
        if f:
            p = f/n
            ent -= p*math.log2(p)
    return ent

def human_time(sec):
    if sec<60: return f"{sec:.2f}s"
    m = sec/60
    if m<60: return f"{m:.2f}m"
    h = m/60
    if h<24: return f"{h:.2f}h"
    d = h/24
    if d<365: return f"{d:.2f}d"
    return f"{d/365:.2f}y"

BANNER = r"""
--     ___________   __       ___      ___      ___  ___           __      ___         _______    __    __       __      
--    ("     _   ") /""\     |"  \    /"  |    |"  \/"  |         /""\    |"  |       |   __ "\  /" |  | "\     /""\     
--     )__/  \\__/ /    \     \   \  //   |     \   \  /         /    \   ||  |       (. |__) :)(:  (__)  :)   /    \    
--        \\_ /   /' /\  \    /\\  \/.    |      \\  \/         /' /\  \  |:  |       |:  ____/  \/      \/   /' /\  \   
--        |.  |  //  __'  \  |: \.        |      /\.  \        //  __'  \  \  |___    (|  /      //  __  \\  //  __'  \  
--        \:  | /   /  \\  \ |.  \    /:  |     /  \   \      /   /  \\  \( \_|:  \  /|__/ \    (:  (  )  :)/   /  \\  \ 
--         \__|(___/    \___)|___|\__/|___|    |___/\___|    (___/    \___)\_______)(_______)    \__|  |__/(___/    \___)
--                                                                                                                         
           0xCG // CYBER GHOSTS — TAMxALPHA
"""

# ---------------- Tools (1..30) ----------------

# 1 System Recon (cross-platform)
def sys_recon():
    ok("System Recon")
    try:
        print("Platform:", platform.system(), platform.release())
        print("Machine:", platform.machine())
        print("Python:", platform.python_version())
        if is_posix():
            if Path("/proc/meminfo").exists():
                lines = Path("/proc/meminfo").read_text().splitlines()[:4]
                print("Memory (sample):")
                for l in lines: print("  "+l)
    except Exception as e:
        warn("Recon limited: "+str(e))
    pause()

# 2 Port Scanner (threaded)
def port_scanner():
    target = input("Target IP/host: ").strip()
    rng = input("Range (1-1024) [1-1024]: ").strip() or "1-1024"
    timeout = float(input("Timeout sec [0.3]: ").strip() or "0.3")
    try:
        s,e = [int(x) for x in rng.split("-",1)]
    except:
        err("Invalid range"); return pause()
    ok(f"Scanning {target} ports {s}-{e}")
    open_ports=[]
    lock=threading.Lock()
    def scan(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sck:
                sck.settimeout(timeout)
                if sck.connect_ex((target,p))==0:
                    with lock:
                        open_ports.append(p); print(Fore.GREEN+f"[OPEN] {p}"+Style.RESET_ALL)
        except Exception:
            pass
    threads=[]
    for port in range(s,e+1):
        t=threading.Thread(target=scan,args=(port,),daemon=True); threads.append(t); t.start()
        if len(threads)%300==0:
            for tt in threads[-300:]: tt.join()
    for tt in threads: tt.join()
    hr(); ok(f"Open ports: {sorted(open_ports)}")
    pause()

# 3 Banner Grabber
def banner_grabber():
    host = input("Host: ").strip()
    port = int(input("Port [80]: ").strip() or "80")
    try:
        with socket.create_connection((host,port), timeout=4) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            s.settimeout(2)
            data = s.recv(4096)
            ok("Banner:")
            print(data.decode(errors="ignore"))
    except Exception as e:
        err(str(e))
    pause()

# 4 Hash Utility
def hash_util():
    mode = input("[1] Text  [2] File -> ").strip() or "1"
    if mode=="1":
        t = input("Text: ").encode()
        print("MD5   :", hashlib.md5(t).hexdigest())
        print("SHA1  :", hashlib.sha1(t).hexdigest())
        print("SHA256:", hashlib.sha256(t).hexdigest())
    else:
        p = Path(input("File path: ").strip())
        if not p.exists(): err("File not found"); return pause()
        h=hashlib.sha256()
        with p.open("rb") as f:
            for ch in iter(lambda: f.read(1<<20), b""): h.update(ch)
        print("SHA256:", h.hexdigest())
    pause()

# 5 File Integrity (baseline / verify)
def file_integrity_checker():
    root = Path(input("Directory [.] : ").strip() or ".")
    manifest = Path(input("Manifest path [manifest.json]: ").strip() or "manifest.json")
    mode = input("[1] Create baseline  [2] Verify -> ").strip() or "1"
    def sha256file(p):
        h=hashlib.sha256()
        with p.open("rb") as f:
            for ch in iter(lambda: f.read(1<<20), b""): h.update(ch)
        return h.hexdigest()
    if mode=="1":
        data={}
        for dp,_,files in os.walk(root):
            for fn in files:
                p=Path(dp)/fn
                try:
                    st=p.stat()
                    data[str(p)]={"size":st.st_size,"mtime":st.st_mtime,"sha256":sha256file(p)}
                except Exception as e:
                    warn(f"skip {p}: {e}")
        manifest.write_text(json.dumps(data,indent=2))
        ok(f"Baseline saved: {manifest}")
    else:
        if not manifest.exists(): err("Manifest not found"); return pause()
        base=json.loads(manifest.read_text())
        changed=0
        for path,meta in base.items():
            p=Path(path)
            if not p.exists():
                print(Fore.RED+f"[MISSING] {path}"+Style.RESET_ALL); changed+=1; continue
            cur_sha=sha256file(p)
            if cur_sha!=meta.get("sha256"):
                print(Fore.RED+f"[MODIFIED] {path}"+Style.RESET_ALL); changed+=1
        if changed==0: ok("All files intact") 
        else: warn(f"{changed} discrepancies")
    pause()

# 6 Password Generator
def password_gen():
    l=int(input("Length [16]: ").strip() or "16")
    symbols = input("Include symbols? [y/N]: ").strip().lower() == "y"
    pool = string.ascii_letters + string.digits + ( "!@#$%^&*()-_=+[]{};:,.?/\\|" if symbols else "" )
    rnd = random.SystemRandom()
    pwd="".join(rnd.choice(pool) for _ in range(l))
    ok("Password: " + Fore.GREEN + Style.BRIGHT + pwd)
    pause()

# 7 Encoder/Decoder (Base64/Hex)
def encoder_decoder():
    mode = input("[1] Base64  [2] Hex -> ").strip() or "1"
    act = input("[E]ncode / [D]ecode -> ").strip().lower() or "e"
    s = input("Input: ").encode()
    try:
        if mode=="1":
            out = base64.b64encode(s) if act=="e" else base64.b64decode(s)
        else:
            out = s.hex().encode() if act=="e" else bytes.fromhex(s.decode())
        ok("Output:"); print(out.decode(errors="ignore"))
    except Exception as e:
        err(str(e))
    pause()

# 8 XOR Cipher (file)
def xor_cipher():
    src = Path(input("Input file: ").strip())
    if not src.exists(): err("File not found"); return pause()
    dst = Path(input("Output file [src.xor]: ").strip() or (str(src)+".xor"))
    key = input("Key (text): ").encode()
    if not key: err("Key empty"); return pause()
    out=bytearray()
    i=0
    with src.open("rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            for b in chunk:
                out.append(b ^ key[i % len(key)])
                i+=1
    dst.write_bytes(out)
    ok(f"Wrote {dst}")
    pause()

# 9 Stego Detector (simple LSB heuristic)
def stego_detector():
    p = Path(input("Image file (PNG/JPEG) path: ").strip())
    if not p.exists(): err("File not found"); return pause()
    data = p.read_bytes()
    sample = data[:10000]
    bits = sum(bin(b).count("1") for b in sample)
    dens = bits / (len(sample)*8)
    print(f"Sample bit density: {dens:.3f}")
    if dens < 0.45:
        warn("Low bit-density: possible stego or heavy zeros (heuristic)")
    else:
        ok("No obvious LSB anomalies in sample (heuristic only)")
    pause()

# 10 Entropy Heatmap (directory/file)
def entropy_heatmap():
    p = Path(input("File or directory: ").strip())
    thr=float(input("Threshold (e.g., 7.5): ").strip() or "7.5")
    files=[]
    if p.is_dir():
        for dp,_,fs in os.walk(p):
            for f in fs: files.append(Path(dp)/f)
    elif p.is_file():
        files=[p]
    else:
        err("Path not found"); return pause()
    for f in files:
        try:
            data=f.read_bytes()[:1<<20]
            e=_entropy(data)
            color=Fore.RED if e>=thr else Fore.GREEN
            print(color + f"{f} -> entropy {e:.2f}" + Style.RESET_ALL)
        except Exception as ex:
            warn(f"{f}: {ex}")
    pause()

# 11 Forensic File Carver
def forensic_carver():
    src = Path(input("Raw input file (e.g. disk image): ").strip())
    if not src.exists(): err("Input not found"); return pause()
    outdir = Path(input("Output dir [carved]: ").strip() or "carved"); outdir.mkdir(parents=True,exist_ok=True)
    data = src.read_bytes()
    count=0
    # JPEG
    i=0
    while True:
        i = data.find(b"\xff\xd8", i)
        if i<0: break
        j = data.find(b"\xff\xd9", i+2)
        if j<0: break
        out = outdir/f"carve_{count:03d}.jpg"; out.write_bytes(data[i:j+2]); count+=1; i=j+2
    # PNG
    sig=b"\x89PNG\r\n\x1a\n"
    i=0
    while True:
        i = data.find(sig,i)
        if i<0: break
        j = data.find(b"\x00\x00\x00\x00IEND", i+8)
        if j<0: break
        j_end=j+12
        out = outdir/f"carve_{count:03d}.png"; out.write_bytes(data[i:j_end]); count+=1; i=j_end
    # PDF
    i=0
    while True:
        i = data.find(b"%PDF", i)
        if i<0: break
        j = data.find(b"%%EOF", i+4)
        if j<0: break
        out = outdir/f"carve_{count:03d}.pdf"; out.write_bytes(data[i:j+5]); count+=1; i=j+5
    if count: ok(f"Carved {count} files into {outdir}")
    else: warn("No known signatures found")
    pause()

# 12 Regex Extractor Pro
PAT_EMAIL = re.compile(rb"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}")
PAT_URL   = re.compile(rb"https?://[^\s\"'<>]+")
PAT_IPV4  = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PAT_JWT   = re.compile(rb"[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
def regex_extractor():
    path=input("File path (leave empty to paste text): ").strip()
    if path:
        data = Path(path).read_bytes()
    else:
        data = input("Paste text: ").encode()
    found = {
        "emails": set(m.decode() for m in PAT_EMAIL.findall(data)),
        "urls": set(m.decode() for m in PAT_URL.findall(data)),
        "ips": set(m.decode() for m in PAT_IPV4.findall(data)),
        "jwts": set(m.decode() for m in PAT_JWT.findall(data)),
    }
    for k,v in found.items():
        color = Fore.GREEN if v else Fore.YELLOW
        print(color + f"{k.upper()} ({len(v)}):" + Style.RESET_ALL)
        for it in sorted(v): print("  "+it)
    pause()

# 13 Crypto Analyzer
def crypto_analyzer():
    s=input("String/hex/base64: ").strip()
    tried=False
    def is_hex(s):
        s2=s.strip().lower(); return len(s2)%2==0 and all(c in "0123456789abcdef" for c in s2)
    def looks_b64(s):
        s2=s.strip(); return len(s2)%4==0 and re.fullmatch(r"[A-Za-z0-9+/=]+", s2) is not None
    if is_hex(s):
        tried=True
        try:
            b=bytes.fromhex(s)
            ok("HEX -> UTF8:"); print(b.decode())
        except: ok("HEX -> bytes:"); print(bytes.fromhex(s))
    if looks_b64(s):
        tried=True
        try:
            b=base64.b64decode(s, validate=True)
            ok("Base64 -> utf8:"); print(b.decode())
        except Exception:
            ok("Base64 -> bytes:"); print(base64.b64decode(s))
    try:
        import codecs
        r=codecs.decode(s, "rot_13")
        if r!=s:
            tried=True; ok("ROT13 guess:"); print(r)
    except:
        pass
    if not tried: warn("No clear guess — try encoder/decoder or xor tool")
    pause()

# 14 Local Network Scanner (ICMP ping sweep)
def _ping_once(ip,timeout=1):
    if os.name=="nt":
        cmd=["ping","-n","1","-w",str(int(timeout*1000)),ip]
    else:
        cmd=["ping","-c","1","-W",str(int(timeout))]
    try:
        p=subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
        return p.returncode==0
    except Exception:
        return False

def net_scanner():
    base=input("Subnet base (e.g., 192.168.1): ").strip()
    info("Scanning .1-.254 (ICMP ping, may require permissions)")
    live=[]
    lock=threading.Lock()
    def worker(ip):
        if _ping_once(ip):
            with lock:
                live.append(ip); print(Fore.GREEN + f"[UP] {ip}" + Style.RESET_ALL)
    threads=[]
    for i in range(1,255):
        ip=f"{base}.{i}"
        t=threading.Thread(target=worker,args=(ip,),daemon=True)
        threads.append(t); t.start()
        if len(threads)%120==0:
            for x in threads[-120:]: x.join()
    for t in threads: t.join()
    hr(); ok(f"Live hosts: {len(live)}")
    pause()

# 15 Wordlist Tools (mangling)
LEET = str.maketrans({"a":"4","e":"3","i":"1","o":"0","s":"5","t":"7"})
def wordlist_tools():
    base = input("Base words (space separated): ").strip().split()
    if not base: err("No words provided"); return pause()
    out=set()
    suffixes=["","123","!","2025","@","_","99"]
    for w in base:
        variants={w, w.lower(), w.upper(), w.capitalize(), w.translate(LEET)}
        for v in variants:
            for sfx in suffixes:
                out.add(v+sfx); out.add(sfx+v)
    ok(f"Generated {len(out)} unique entries")
    if input("Save to file? [y/N]: ").lower()=="y":
        fn=input("Filename [wordlist.txt]: ").strip() or "wordlist.txt"
        Path(fn).write_text("\n".join(sorted(out)))
        ok(f"Saved {fn}")
    pause()

# 16 Entropy Scanner
def entropy_scanner():
    p = Path(input("File or directory: ").strip())
    thr=float(input("Threshold (e.g., 7.5): ").strip() or "7.5")
    files=[]
    if p.is_dir():
        for dp,_,fs in os.walk(p):
            for f in fs: files.append(Path(dp)/f)
    elif p.is_file():
        files=[p]
    else:
        err("Path not found"); return pause()
    for f in files:
        try:
            data=f.read_bytes()[:1<<20]
            e=_entropy(data)
            color=Fore.RED if e>=thr else Fore.GREEN
            print(color + f"{f} -> entropy {e:.2f}" + Style.RESET_ALL)
        except Exception as ex:
            warn(f"{f}: {ex}")
    pause()

# 17 Binary Analyzer (basic PE/ELF heuristics)
def binary_analyzer():
    p=Path(input("Binary path: ").strip())
    if not p.exists(): err("File not found"); return pause()
    data = p.read_bytes()
    if data.startswith(b"MZ"):
        ok("PE (Windows) detected")
        try:
            e_lfanew = int.from_bytes(data[0x3c:0x40], 'little')
            machine = int.from_bytes(data[e_lfanew+4:e_lfanew+6], 'little')
            print(f"PE e_lfanew: {e_lfanew}, machine: 0x{machine:x}")
        except Exception as e:
            warn("PE header parse failed: "+str(e))
    elif data.startswith(b"\x7fELF"):
        ok("ELF detected")
        try:
            ei_class = data[4]; print("ELF class:", "64-bit" if ei_class==2 else "32-bit")
        except:
            pass
    else:
        warn("Unknown/other binary format")
    ent=_entropy(data[:1<<20])
    print(f"Entropy (first 1MB): {ent:.2f}")
    pause()

# 18 Log Analyzer (simple)
def log_analyzer():
    p = Path(input("Log file path: ").strip())
    if not p.exists(): err("File not found"); return pause()
    data = p.read_text(errors="ignore").splitlines()
    total = len(data)
    ips={}
    errs=0
    for ln in data:
        m=re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ln)
        if m:
            ips[m.group(0)] = ips.get(m.group(0),0)+1
        if "error" in ln.lower() or "fail" in ln.lower(): errs+=1
    ok(f"Lines: {total}  Errors/failures (approx): {errs}")
    top = sorted(ips.items(), key=lambda x:-x[1])[:10]
    print("Top IPs:")
    for ip,c in top: print(f"  {ip} -> {c}")
    pause()

# 19 SBOM-lite (local)
def sbom_lite():
    root = Path(input("Project dir [.]: ").strip() or ".")
    files = ["requirements.txt","Pipfile.lock","package.json","go.mod","Gemfile.lock"]
    found={}
    for fn in files:
        p = Path(root)/fn
        if p.exists():
            try:
                found[fn]=p.read_text(errors="ignore").splitlines()
            except: found[fn]="(read error)"
    if not found:
        warn("No common dependency files found")
    else:
        ok("Found dependency files:")
        for k,v in found.items():
            print(Fore.CYAN + f"== {k} ==" + Style.RESET_ALL)
            if isinstance(v,list):
                for line in v[:50]: print("  "+line)
            else:
                print("  "+str(v))
    pause()

# 20 Dockerfile Auditor
def dockerfile_audit():
    p = Path(input("Dockerfile path: ").strip() or "Dockerfile")
    if not p.exists(): err("Dockerfile not found"); return pause()
    s = p.read_text()
    issues=[]
    if "ADD " in s:
        issues.append("Usage of ADD (prefer COPY)")
    if "USER root" in s or "USER 0" in s:
        issues.append("Running as root user found")
    if re.search(r"apt-get install .* -y", s) and "rm -rf /var/lib/apt/lists" not in s:
        issues.append("apt packages installed without cleanup")
    if "EXPOSE 22" in s:
        issues.append("Exposes SSH port (careful)")
    if issues:
        warn("Issues found:")
        for it in issues: print("  - "+it)
    else:
        ok("No obvious issues detected")
    pause()

# 21 Password Policy Auditor (single/wordlist)
def password_policy_auditor():
    def entropy_est(s):
        import math, collections
        if not s: return 0.0
        freq = collections.Counter(s)
        n = len(s)
        ent = 0.0
        for c,f in freq.items():
            p = f/n
            ent -= p * math.log2(p)
        return ent

    mode = input("[1] Single password  [2] Wordlist -> ").strip() or "1"
    if mode=="1":
        pwd = input("Password: ").strip()
        ent = entropy_est(pwd)
        checks = []
        checks.append(("length", len(pwd)))
        checks.append(("entropy", round(ent,2)))
        checks.append(("has_upper", any(c.isupper() for c in pwd)))
        checks.append(("has_lower", any(c.islower() for c in pwd)))
        checks.append(("has_digit", any(c.isdigit() for c in pwd)))
        checks.append(("has_symbol", any(not c.isalnum() for c in pwd)))
        print(Fore.CYAN + "Password audit:")
        for k,v in checks:
            print(f"  {k:12}: {v}")
        weak_reasons = []
        if len(pwd) < 10: weak_reasons.append("too short (<10)")
        if ent < 3.5: weak_reasons.append("low entropy")
        if re.search(r"(?:\d{4,})", pwd): weak_reasons.append("contains long digit sequence (possible year)")
        if re.search(r"(abcdef|qwerty|12345|password)", pwd.lower()):
            weak_reasons.append("common pattern")
        if weak_reasons:
            print(Fore.RED + "[WEAK] Reasons: " + ", ".join(weak_reasons) + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[OK] Looks reasonably strong" + Style.RESET_ALL)
    else:
        fn = input("Wordlist path: ").strip()
        p = Path(fn)
        if not p.exists(): err("File not found"); return pause()
        small=0; total=0
        for line in p.read_text(errors="ignore").splitlines():
            total+=1
            if len(line.strip())<10:
                small+=1
        print(Fore.CYAN + f"Total words: {total}, <10 chars: {small}" + Style.RESET_ALL)
        if small>0: warn("Many short entries; consider filtering")
    pause()

# 22 Hash Identifier
def hash_identifier():
    h = input("Hash value (paste): ").strip()
    L = len(h)
    guess=[]
    if re.fullmatch(r"[0-9a-fA-F]+", h):
        if L==32: guess.append("MD5 / NTLM (32 hex)")
        if L==40: guess.append("SHA1 (40 hex)")
        if L==64: guess.append("SHA256 (64 hex)")
        if L==128: guess.append("SHA512 (128 hex)")
    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", h):
        guess.append("maybe Base64-encoded blob or bcrypt/other")
    print(Fore.CYAN + "Guessed algorithms:" + Style.RESET_ALL)
    if guess:
        for g in guess: print("  - " + g)
    else:
        print(Fore.YELLOW + "Unknown/ambiguous. Could be salted/encoded/other." + Style.RESET_ALL)
    pause()

# 23 Local Leak Checker
def local_leak_checker():
    breach = Path(input("Local breached-hashes file path: ").strip())
    if not breach.exists(): err("Breach file not found"); return pause()
    target = input("[1] Single hash  [2] File of hashes/users -> ").strip() or "1"
    lines = [ln.strip() for ln in breach.read_text(errors="ignore").splitlines() if ln.strip()]
    set_lines = set(lines)
    if target=="1":
        h = input("Hash to check: ").strip()
        if h in set_lines:
            print(Fore.RED + "[FOUND] Hash exists in local breach DB" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[NOT FOUND] Not present in local DB" + Style.RESET_ALL)
    else:
        fn = input("Path to target list: ").strip()
        p = Path(fn)
        if not p.exists(): err("File not found"); return pause()
        matches=0
        for t in p.read_text(errors="ignore").splitlines():
            t=t.strip()
            if not t: continue
            if t in set_lines:
                print(Fore.RED + f"[FOUND] {t}" + Style.RESET_ALL); matches+=1
        ok(f"Total matches: {matches}")
    pause()

# 24 Password Cracking Simulator (estimator)
def cracking_simulator():
    charset_map = {"lower": 26, "upper":26, "digits":10, "symbols": 32}
    use_lower = input("Include lowercase? [Y/n]: ").strip().lower() != "n"
    use_upper = input("Include UPPER? [y/N]: ").strip().lower() == "y"
    use_digits = input("Include digits? [Y/n]: ").strip().lower() != "n"
    use_symbols = input("Include symbols? [y/N]: ").strip().lower() == "y"
    length = int(input("Password length (estimate): ").strip() or "8")
    hashes_per_sec = float(input("Attacker speed (hashes/sec) [e.g., 1000000]: ").strip() or "1000000")
    charset = 0
    if use_lower: charset += charset_map["lower"]
    if use_upper: charset += charset_map["upper"]
    if use_digits: charset += charset_map["digits"]
    if use_symbols: charset += charset_map["symbols"]
    if charset==0: err("Empty charset"); return pause()
    total = float(charset) ** length
    avg = total/2.0
    secs = avg / hashes_per_sec
    def human(sec):
        if sec<60: return f"{sec:.2f}s"
        m = sec/60
        if m<60: return f"{m:.2f}m"
        h = m/60
        if h<24: return f"{h:.2f}h"
        d = h/24
        if d<365: return f"{d:.2f}d"
        return f"{d/365:.2f}y"
    print(Fore.CYAN + "Estimates (average bruteforce time):")
    print(f"  Keyspace size : {int(total):,}")
    print(f"  Avg tries     : {int(avg):,}")
    print(f"  Attacker speed: {int(hashes_per_sec):,} H/s")
    print(Fore.YELLOW + f"  Estimated avg time: {human(secs)}" + Style.RESET_ALL)
    pause()

# 25 Hash Validator
def hash_validator():
    alg = input("Algorithm (md5/sha1/sha256/sha512): ").strip().lower() or "sha256"
    candidate = input("Candidate password: ")
    target_hash = input("Target hash (hex): ").strip()
    computed = ""
    b = candidate.encode()
    if alg=="md5": computed = hashlib.md5(b).hexdigest()
    elif alg=="sha1": computed = hashlib.sha1(b).hexdigest()
    elif alg=="sha256": computed = hashlib.sha256(b).hexdigest()
    elif alg=="sha512": computed = hashlib.sha512(b).hexdigest()
    else:
        err("Unsupported algorithm"); return pause()
    if computed.lower()==target_hash.lower():
        ok("MATCH")
    else:
        warn("No match")
    pause()

# 26 ELF Hardening Auditor (heuristic)
def elf_hardening_audit():
    p = Path(input("ELF/PE binary path: ").strip())
    if not p.exists():
        err("File not found"); return pause()
    data = p.read_bytes()
    if data.startswith(b"\x7fELF"):
        ok("ELF detected — running checks")
        try:
            ei_class = data[4]
            is64 = (ei_class==2)
            endian = 'little' if data[5]==1 else 'big'
            print(f"Class: {'64-bit' if is64 else '32-bit'}, Endian: {endian}")
            has_relro = b'GNU_RELRO' in data or b'.rel.ro' in data
            canary = b'__stack_chk_fail' in data
            e_type = int.from_bytes(data[16:18], 'little')
            pie = (e_type == 3)
            print("Checks:")
            print("  RELRO (heuristic)     :", Fore.GREEN + "Yes" + Style.RESET_ALL if has_relro else Fore.YELLOW + "Partial/Unknown" + Style.RESET_ALL)
            print("  Stack Canary present  :", Fore.GREEN + "Yes" + Style.RESET_ALL if canary else Fore.RED + "No" + Style.RESET_ALL)
            print("  NX (stack exec protected):", Fore.GREEN + "Likely" + Style.RESET_ALL)
            print("  PIE (ET_DYN heuristics):", Fore.GREEN + "Likely" + Style.RESET_ALL if pie else Fore.YELLOW + "Probably not (ET_EXEC)" + Style.RESET_ALL)
        except Exception as e:
            err("ELF parse error: " + str(e))
    elif data.startswith(b"MZ"):
        ok("PE (Windows) detected — running limited checks")
        try:
            e_lfanew = int.from_bytes(data[0x3c:0x40], 'little')
            dll_chars = int.from_bytes(data[e_lfanew+0x5e:e_lfanew+0x60], 'little')
            ASLR_FLAG = 0x40
            DEP_FLAG = 0x100
            print("DLL characteristics (hex): 0x%x" % dll_chars)
            print("  ASLR (DynamicBase):", Fore.GREEN+"Yes"+Style.RESET_ALL if (dll_chars & ASLR_FLAG) else Fore.RED+"No"+Style.RESET_ALL)
            print("  DEP (NX)           :", Fore.GREEN+"Yes"+Style.RESET_ALL if (dll_chars & DEP_FLAG) else Fore.RED+"No"+Style.RESET_ALL)
        except Exception as e:
            warn("PE parse minimal failed: " + str(e))
    else:
        err("Unknown/unsupported binary format for this auditor.")
    pause()

# 27 ROP Gadget Finder (basic + Capstone if available)
def rop_gadget_finder():
    p = Path(input("Binary path: ").strip())
    if not p.exists(): err("File not found"); return pause()
    data = p.read_bytes()
    max_gadget_len = int(input("Max gadget length bytes [6]: ").strip() or "6")
    hits=[]
    for i in range(len(data)):
        if data[i] in (0xc3,0xcb,0xc2,0xca):  # x86 ret-like
            start = max(0, i - max_gadget_len)
            gadget = data[start:i+1]
            hits.append((start, gadget))
    if not hits:
        warn("No simple 'ret' gadgets found (binary may be stripped/arch mismatch)")
    else:
        ok(f"Found {len(hits)} gadget candidates (showing first 50):")
        if HAS_CAPSTONE:
            info("Disassembling candidates with Capstone (x86_64 then x86_32)")
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            shown=0
            for off,g in hits[:200]:
                # try 64-bit
                try:
                    cs = Cs(CS_ARCH_X86, CS_MODE_64)
                    ins = list(cs.disasm(g, off))
                except Exception:
                    ins=[]
                if not ins:
                    try:
                        cs = Cs(CS_ARCH_X86, CS_MODE_32)
                        ins = list(cs.disasm(g, off))
                    except:
                        ins=[]
                if ins:
                    print(Fore.CYAN + f"0x{off:08x}" + Style.RESET_ALL)
                    for ii in ins[-6:]:
                        print(f"  0x{ii.address:x}:\t{ii.mnemonic}\t{ii.op_str}")
                else:
                    hx = " ".join(f"{b:02x}" for b in g)
                    printable = "".join((chr(b) if 32<=b<127 else ".") for b in g)
                    print(f"0x{off:08x}: {hx}   | {printable}")
                shown+=1
                if shown>=50: break
        else:
            for off,g in hits[:50]:
                hx = " ".join(f"{b:02x}" for b in g)
                printable = "".join((chr(b) if 32<=b<127 else ".") for b in g)
                print(f"0x{off:08x}: {hx}   | {printable}")
    pause()

# 28 Shellcode Analyzer (no exec) with optional Capstone disasm
def shellcode_analyzer():
    mode = input("[1] Load from file  [2] Paste hex -> ").strip() or "1"
    if mode=="1":
        p = Path(input("Shellcode file path: ").strip())
        if not p.exists(): err("File not found"); return pause()
        data = p.read_bytes()
    else:
        hx = input("Hex (no 0x, spaces allowed): ").strip().replace(" ", "")
        try:
            data = bytes.fromhex(hx)
        except:
            err("Invalid hex"); return pause()
    print(f"Length: {len(data)} bytes")
    ent = _entropy(data)
    print(f"Entropy (first 1MB): {ent:.2f}")
    nulls = data.count(0)
    print("Null bytes:", nulls)
    strs = re.findall(rb"[ -~]{4,}", data)
    if strs:
        print(Fore.GREEN + "Strings found (short):" + Style.RESET_ALL)
        for s in strs[:10]:
            print("  "+s.decode(errors="replace"))
    else:
        warn("No printable strings >=4 chars found")
    syscall_hits = []
    for i in range(len(data)-1):
        if data[i]==0x0f and data[i+1]==0x05:
            syscall_hits.append(("syscall", i))
        if data[i]==0xcd and data[i+1]==0x80:
            syscall_hits.append(("int80", i))
    if syscall_hits:
        ok(f"Syscall-like opcodes found: {len(syscall_hits)}")
        for t,i in syscall_hits[:10]:
            print(f" {t} at offset 0x{i:x}")
    if HAS_CAPSTONE:
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            def show_disasm(code, mode, label):
                cs = Cs(CS_ARCH_X86, mode)
                cs.detail=False
                ins = list(cs.disasm(code, 0x1000))
                if not ins:
                    print(Fore.YELLOW + f"No instructions for {label}" + Style.RESET_ALL)
                    return
                print(Fore.CYAN + f"Disassembly ({label}) — first 80 insns:" + Style.RESET_ALL)
                for ii in ins[:80]:
                    print(f"0x{ii.address:x}:\t{ii.mnemonic}\t{ii.op_str}")
            show_disasm(data, CS_MODE_64, "x86_64")
            show_disasm(data, CS_MODE_32, "x86_32")
        except Exception as e:
            warn("Capstone disasm error: "+str(e))
    pause()

# 29 Firmware / Image Analyzer
def firmware_analyzer():
    p = Path(input("Firmware/image file path: ").strip())
    if not p.exists(): err("File not found"); return pause()
    data = p.read_bytes()
    print(f"Size: {len(data):,} bytes")
    sigs = {
        "squashfs": b"hsqs",
        "JFFS2": b"JFFS2",
        "UBI": b"UBI#",
        "uImage": b"U-Boot",
        "gzip": b"\x1f\x8b\x08",
    }
    found=[]
    for k,v in sigs.items():
        if v in data[:4096] or v in data:
            found.append(k)
    if found:
        ok("Found likely components: " + ", ".join(found))
    else:
        warn("No common FS signatures found (could be raw blob)")
    strs = re.findall(rb"[!-~]{6,}", data[:200000])
    if strs:
        print(Fore.GREEN + "Some notable strings (sample):" + Style.RESET_ALL)
        for s in strs[:20]:
            print("  "+s.decode(errors="ignore"))
    else:
        warn("Few strings in sampled region")
    window = 4096
    hotspots=[]
    for i in range(0, min(len(data), 1<<20), window):
        chunk = data[i:i+window]
        e = _entropy(chunk)
        if e > 7.5:
            hotspots.append((i, e))
    if hotspots:
        ok(f"High-entropy regions (sampled): {len(hotspots)}")
        for off,e in hotspots[:10]:
            print(f"  offset 0x{off:x}: entropy {e:.2f}")
    else:
        info("No major high-entropy regions in sample")
    pause()

# 30 ASLR Entropy Tester (Linux)
def aslr_entropy_tester():
    if os.name!="posix" or not Path("/proc").exists():
        err("ASLR tester requires Linux-like /proc"); return pause()
    runs = int(input("Spawn count (e.g., 30): ").strip() or "30")
    target_cmd = input("Command to spawn [ /bin/true ]: ").strip() or "/bin/true"
    bases=[]
    info("Spawning processes and reading /proc/<pid>/maps base addresses (requires permission)")
    for i in range(runs):
        try:
            p = subprocess.Popen([target_cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.05)
            try:
                maps = Path(f"/proc/{p.pid}/maps").read_text(errors="ignore")
            except:
                maps = ""
            m = re.search(r"([0-9a-f]+)-[0-9a-f]+ .*", maps)
            if m:
                bases.append(int(m.group(1),16))
            else:
                bases.append(0)
            p.wait(timeout=1)
        except Exception:
            bases.append(0)
    nonzero = [b for b in bases if b!=0]
    if not nonzero:
        warn("No address data (insufficient privileges or flat maps)")
    else:
        vals = [((b>>12) & 0xffff) for b in nonzero]
        uniq = len(set(vals))
        ok(f"Samples: {len(vals)}, Unique base pages: {uniq}")
        if uniq < max(2, len(vals)//4):
            warn("ASLR may have low variance (low entropy)")
        else:
            ok("ASLR shows reasonable variation")
    pause()

# ---------------- Developer Contact placeholder ----------------
def developer_contact():
    hr(Fore.CYAN)
    print(Fore.CYAN + "alpha-0.2-pk@proton.me")
    hr(Fore.CYAN)
    pause()

# ---------------- Menu mapping ----------------
MENU = {
 "1": ("System Recon", sys_recon),
 "2": ("Port Scanner", port_scanner),
 "3": ("Banner Grabber", banner_grabber),
 "4": ("Hash Utility", hash_util),
 "5": ("File Integrity Checker", file_integrity_checker),
 "6": ("Password Generator", password_gen),
 "7": ("Encoder/Decoder (Base64/Hex)", encoder_decoder),
 "8": ("XOR Cipher (file)", xor_cipher),
 "9": ("Stego Detector (heuristic)", stego_detector),
 "10":("Entropy Heatmap (dir/file)", entropy_heatmap),
 "11":("Forensic File Carver", forensic_carver),
 "12":("Regex Extractor Pro", regex_extractor),
 "13":("Crypto Analyzer (guess)", crypto_analyzer),
 "14":("Local Net Scanner (ping sweep)", net_scanner),
 "15":("Wordlist Mangler", wordlist_tools),
 "16":("Entropy Scanner", entropy_scanner),
 "17":("Binary Analyzer (PE/ELF)", binary_analyzer),
 "18":("Log Analyzer (nginx/ssh)", log_analyzer),
 "19":("SBOM-lite (local deps)", sbom_lite),
 "20":("Dockerfile Auditor", dockerfile_audit),
 "21":("Password Policy Auditor", password_policy_auditor),
 "22":("Hash Identifier", hash_identifier),
 "23":("Local Leak Checker", local_leak_checker),
 "24":("Password Cracking Simulator (estimator)", cracking_simulator),
 "25":("Hash Validator (local)", hash_validator),
 "26":("ELF Hardening Auditor", elf_hardening_audit),
 "27":("ROP Gadget Finder (basic)", rop_gadget_finder),
 "28":("Shellcode Analyzer (no exec)", shellcode_analyzer),
 "29":("Firmware / Image Analyzer", firmware_analyzer),
 "30":("ASLR Entropy Tester (Linux)", aslr_entropy_tester),
 "99":("Developer Contact", developer_contact),
 "0": ("Exit", sys.exit),
}

# ---------------- Main ----------------
def main():
    try:
        require_whatsapp_follow()
        while True:
            clear()
            print(Fore.GREEN + Style.BRIGHT + BANNER + Style.RESET_ALL)
            hr()
            capnote = "yes" if HAS_CAPSTONE else "no"
            print(Fore.YELLOW + f"Platform={sys.platform}  termux={'yes' if in_termux() else 'no'}  capstone={capnote}" + Style.RESET_ALL)
            hr()
            for k in sorted(MENU, key=lambda x: (x!="0", x!="99", int(x) if x.isdigit() else 9999)):
                title = MENU[k][0]
                color = Fore.GREEN if k not in ("0","99") else (Fore.CYAN if k=="99" else Fore.RED)
                print(color + f"{k:>3}. {title}" + Style.RESET_ALL)
            hr()
            choice = input(Fore.YELLOW + "Select: " + Style.RESET_ALL).strip()
            clear()
            if choice in MENU:
                print(Fore.GREEN + f"== {MENU[choice][0]} ==" + Style.RESET_ALL)
                try:
                    MENU[choice][1]()
                except KeyboardInterrupt:
                    warn("Interrupted.")
                except SystemExit:
                    raise
                except Exception as e:
                    err("Tool error: " + str(e))
                    pause()
            else:
                err("Invalid choice"); time.sleep(0.6)
    except KeyboardInterrupt:
        print(); err("Keyboard Interrupt — exiting safely."); sys.exit(0)

if __name__ == "__main__":
    main()
