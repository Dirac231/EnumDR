tcp(){
    echo -e "\nTCP SCAN\n"
    sudo nmap -p- -Pn -sC -sV -v --min-rate 800 --open --reason $1 -o tcp_$1.txt
    ports=$(cat tcp_$1.txt | grep "^[0-9]" | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$// | awk '{print $1}')
    sudo rm tcp_$1.txt
}

udp(){
    echo -e "\nUDP TOP 2000 SCAN\n"
    sudo nmap -sUV -Pn -v --version-intensity 0 --top-ports 2000 --scan-delay 950ms --open --reason $1

    echo -e "\nFULL UDP SCAN\n"
    sudo nmap -sUV -Pn -v --version-intensity 0 -p- --scan-delay 950ms --open --reason $1
}

proxyscan(){
    echo -e "\nSCANNING TOP 8351 \n"
    proxychains sudo nmap -v -sTV -Pn --top-ports 8351 $1 > proxyscan_$1.txt
}

tftpscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -p$2 -sU --script tftp-enum $1
}

ftpscan(){
    echo -e "\nNMAP SCANNING\n"
    sudo nmap -Pn -sV --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p$2 $1

    echo -e "\nDEFAULT CREDS\n"
    hydra -V -t 10 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$1:$2
}

sshscan(){
    echo -e "\nNMAP SCANNING\n"
    sudo nmap -p$2 -sV -Pn -T4 --script="ssh-* and not (brute) and not (run)" $1

    echo -e "\nDEFAULT CREDS\n"
    hydra -V -t 10 -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt -e nsr -f ssh://$1:$2
}

telnetscan(){
    echo -e "\nENUMERATION\n"
    nmap -n -sV -Pn --script "*telnet* and safe" -p$2 $1
}

smtpscan(){
        echo -e "\nENUMERATION\n"
        sudo nmap --script=smtp-ntlm-info,smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p$2 -Pn $1

        echo -e "\nMETHOD: "
        read $method

        echo -e "\nLIST TO EMPLOY: "
        read $users

        echo -e "\nGUESSING USERS WITH $method\n"
        smtp-user-enum -M $method -w 10 -U $users -t $1 -p $2
}

dnsscan(){
    echo -e "\nBANNER RETRIEVAL\n"
    dig version.bind CHAOS TXT @$1

    echo -e "\nENUMERATION\n"
    sudo nmap -Pn -n --script "(default and *dns*) or fcrdns or dns-random-txid or dns-random-srcport or broadcast-dhcp-discover" $1 -p$2

    echo -e "\nSIMPLE ZONE TRANSFER\n"
    dig axfr @$1

    echo -e "\nENTER THE DOMAIN\n"
    read domain

    echo -e "\nNMAP SRV-ENUM\n"
    nmap -Pn -n -sCV -p$2 --script dns-srv-enum --script-args dns-srv-enum.domain=$domain $1

    echo -e "\nREVERSE LOOKUP\n"
    dig -x $1

    echo -e "\nATTEMPTING ZONE TRANSFERS\n"
    dig axfr $domain @$1
    dnsenum $domain --dnsserver $1
    fierce --domain $domain --dns-servers $1
}

fingerscan(){
    echo -e "\nSCAN\n"
    sudo nmap -sCV -p$2 $1

    echo -e "\nUSER ENUMERATION: Names.txt\n"
    /home/dirac/OSCP/TOOLS/finger-user-enum/finger-user-enum.pl -p $2 -U /usr/share/seclists/Usernames/Names/names.txt -t $1
}

rpcscan(){
    echo -e "\nRPC SCAN + MAPPING\n"
    rpcinfo $1
    rpcmap.py 'ncacn_ip_tcp:$1'
    sudo nmap -sV -Pn -p$2 --script="msrpc-enum or nfs*" $1

    echo -e "\nANONYMOUS RPC BINDING + ENUM QUERIES\n"
    rpcclient -U "" -N $1 -c dsroledominfo:srvinfo:enumdomains:querydominfo:getdompwinfo:enumdomusers:enumdomgroups:querydispinfo:enumprinters:netshareenumall

    echo -e "\nRPC/SAMR DUMPING\n"
    rpcdump.py $1
    samrdump.py $1
}

snmpscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -sUV -Pn --script=snmp-info -p$2 $1

    echo -e "\nSNMP-CHECK\n"
    snmp-check -p $2 $1 > snmpcheck.txt

    echo -e "\nWALKING MIB WITH PUBLIC\n"
    snmpwalk -v2c -c public -On $1 > snmpwalk_dump.txt

    echo -e "\nSEARCHING VALID SEARCH STRINGS\n"
    onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $1
}

ipmiscan(){
    echo -e "\nENUMERATION\n"
    nmap -sUV --script "ipmi-* and not brute" -p$2 $1
}
imapscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -sCV -Pn --script=imap-ntlm-info -p$2 $1
}

pop3scan(){
    echo -e "\nENUMERATION + WEAK CREDS\n"
    sudo nmap -sV -Pn --script="pop3-*" -p$2 $1
}

identscan(){
    echo -e "\nRETREIVING TCP PORTS\n"
    masscan -p1-65535 $1 --rate=2500 -e $inter > id_ports
    cat id_ports | awk -F ​" "​ ​'{print $4}'​ | awk -F ​"/"​ ​'{print $1}'​ | sort -n | tr ​'\n' ','​ | sed ​'s/,$//'​ > ident_s; rm id_ports

    echo -e "\nSCANNING WITH IDENT\n"
    while read p; do ident-user-enum $1 $p; done < ident_s
}

ntpscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -sUV -Pn --script "ntp* and (discovery or vuln) and not (dos or brute)" -p$2 $1
}

vncscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -sV -Pn -p$2 --script="*vnc* and not brute" $1

    echo -e "\nBRUTEFORCING\n"
    hydra -e nsr -V -t 10 -f -s $2 -P /usr/share/seclists/Passwords/darkweb2017-top10000.txt -t 30 $1 vnc
}

netbscan(){
    echo -e "\nSTANDARD ENUMERATION\n"
    nbtscan -vh $1
    nmblookup -A $1
    sudo nmap -sUV -T4 --script nbstat.nse -p$2 -Pn $1
}

ldapscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -n -sV -p$2 --script "ldap* and not brute" $1
}

smbscan(){
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -sCV -Pn -p$2 $1
        sudo nmap -Pn -p$2 --script="safe or smb-enum-*" $1

        echo -e "\nNTLM-INFO + VERSION\n"
        ntlm-info smb $1
        /home/dirac/OSCP/TOOLS/smbver.sh $1 $2

        echo -e "\nANONYMOUS ACCESS\n"
        smbmap -H $1 -P $2
        smbclient -p $2 -L $1 -U "" --option='client min protocol=NT1'
        smbclient -p $2 -N -L \\\\$1

        echo -e "\n'GUEST' ACCESS\n"
        smbmap -H $1 -u "invalid" -P $2
        smbclient -p $2 -L $1 -U "invalid" --option='client min protocol=NT1'

        echo -e "\nCHECKING KNOWN VULNERABILITIES\n"
        sudo nmap -p$2 --script='smb-vuln-ms*' -Pn $1
        sudo nmap -p$2 --script='smb-vuln-cve*' -Pn $1
        sudo nmap -p$2 --script='smb-vuln-webexec' -Pn $1
        sudo nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -Pn -p$2 $1

        echo -e "\nWEAK CREDENTIALS\n"
        hydra -V -f -t 10 -C /usr/share/seclists/Passwords/Default-Credentials/windows-betterdefaultpasslist.txt -e nsr smb://$1:$2

        echo -e "\nENUM4LINUX\n"
        enum4linux -U -G -r $1
}

ircscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -Pn -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p$2 $1
}

mssqlscan(){
    echo -e "\nSTANDARD ENUMERATION\n"
    sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=$2,mssql.us>

    echo -e "\nDEFAULT CREDENTIALS\n"
    hydra -V -f -t 10 -C /usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt -e nsr mssql://$1:$2
}

mssqlscan(){
    echo -e "\nSTANDARD ENUMERATION\n"
    sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=$2,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -Pn -p$2 $1
    echo -e "\nDEFAULT CREDENTIALS\n"
    hydra -V -f -t 10 -C /usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt -e nsr mssql://$1:$2
}

mongoscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -sV --script "mongo* and default" -Pn -p$2 $1

    echo -e "\nCONNECTION / BANNER\n"
    mongo --host $1
}

rdpscan(){
    echo -e "\nENUMERATION\n"
    sudo nmap -p$2 -Pn -sCV --script=rdp-enum-encryption,rdp-vuln-ms12-020 $1

    echo -e "\nTRYING WINDOWS CREDENTIALS\n"
    hydra -V -f -t 10 -C /usr/share/seclists/Passwords/Default-Credentials/windows-betterdefaultpasslist.txt -e nsr rdp://$1:$2
}

tnscan(){
    echo -e "\nENUMERATION\n"
    tnscmd10g version -p$2 -h $1
    sudo nmap -Pn --script "oracle-tns-version" -p$2 -T4 -sV $1
    oscanner -s $1 -P $2

    echo -e "\nGETTING THE SID\n"
    odat sidguesser -s $1 -p$2
}
