import paramiko
import sys
import getpass

# get hostname
username = ""
port = 22
if len(sys.argv) > 1:
    hostname = sys.argv[1]
    if hostname.find("@") >= 0:
        username, hostname = hostname.split("@")
else:
    hostname = input("Hostname: ")
if len(hostname) == 0:
    print("*** Hostname required.")
    sys.exit(1)

if hostname.find(":") >= 0:
    hostname, portstr = hostname.split(":")
    port = int(portstr)

# get username
if username == "":
    default_username = getpass.getuser()
    username = input("Username [%s]: " % default_username)
    if len(username) == 0:
        username = default_username

pkcs11provider = "/usr/local/lib/opensc-pkcs11.so"
smartcard_pin = getpass.getpass("smartcard pin: ")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
session = paramiko.pkcs11.open_session(pkcs11provider, smartcard_pin)
ssh.connect(hostname, port, username, pkcs11_session=session)
paramiko.pkcs11.close_session(session)
stdin, stdout, stderr = ssh.exec_command("uname -a")
for line in stdout:
    print(line)
