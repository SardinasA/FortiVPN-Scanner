# FG-IR-18-384 (CVE-2018-13379) Scanner/Exploitation Tool
*Exploit allowing for the recovery of cleartext credentials. This tool is provided for testing purposes only. Only run it against infrastructure for which you have recieved permission to test.*

Headnod to those who discovered the exploit, more information by the researcher can be found here: 
https://blog.orange.tw/2019/08/attacking-ssl-vpn-part-2-breaking-the-fortigate-ssl-vpn.html

This exploit was developed to pull the interesting credentials straight out of the binary, rather than require someone to run strings and review the output.

Google Dork: `inurl:remote/login?lang=`

This vulnerability affects the following versions:
```
- FortiOS 6.0 - 6.0.0 to 6.0.4
- FortiOS 5.6 - 5.6.3 to 5.6.7
- FortiOS 5.4 - 5.4.6 to 5.4.12
(other branches and versions than above are not impacted)
ONLY if the SSL VPN service (web-mode or tunnel-mode) is enabled
```

Solutions
Upgrade to FortiOS 5.4.13, 5.6.8, 6.0.5 or 6.2.0 and above.
Check Upgrade path here: https://docs.fortinet.com/upgrade-tool 

Recommendation if Affected
1.	Issue a password change/reset for all users with SSL-VPN access, alert users to changes passwords on other systems if the same password is used.
  a.	Consider MFA implementation.
  b.	Consider Cyber Security Training for all staff
2.	Back up current FortiGate configurations prior to the upgrade.
  a.	Consider reviewing policies
  b.	Consider reviewing FortiGate Hardening Guides: https://docs.fortinet.com/document/fortigate/6.4.0/hardening-your-fortigate/612504/hardening-your-fortigate 
  c.	Consider Geo Restrict Access to Limit access to specific hosts, and specify the addresses of the hosts that are allowed to connect to this VPN.
3.	Download and upgrade the FortiGate (Download current Firmware and Upgrade)
  a.	NOTE: Check Upgrade path here: https://docs.fortinet.com/upgrade-tool 



![Tool in action](https://i.imgur.com/DpKKzsH.png)

## Usage: 

Install Requirements: `pip3 install -r requirements.txt`, then use as below.
```
python3 fortigate.py -h
  ___ ___  ___ _____ ___ ___   _ _____ ___
 | __/ _ \| _ \_   _|_ _/ __| /_\_   _| __|
 | _| (_) |   / | |  | | (_ |/ _ \| | | _|
 |_| \___/|_|_\ |_| |___\___/_/ \_\_| |___|

Extract Useful info (credentials!) from SSL VPN Directory Traversal Vulnerability (FG-IR-18-384)
Tool developed by @x41x41x41 and @DavidStubley

usage: fortigate.py [-h] [-i INPUT] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Target URL or Domain
  -o OUTPUT, --output OUTPUT
                        File to output discovered credentials too
```
