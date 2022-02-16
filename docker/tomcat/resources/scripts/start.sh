#!/bin/sh

IP=$(hostname -I)
echo "[+] IP address of the container: ${IP}" 

echo "[+] Adding gateway address to /etc/hosts file..."
GATEWAY="$(echo ${IP} | cut -f4 -d. --complement).1"
echo "$GATEWAY prevent.reverse.dns" >> /etc/hosts

echo "[+] Preparing /etc/hosts file..."
MOD=$(sed -E "s/${IP}.+/${IP} iinsecure.dev/" /etc/hosts)
echo "${MOD}" > /etc/hosts
echo "127.0.0.1 iinsecure.dev" >> /etc/hosts

echo "[+] Starting tomcat..."
exec catalina.sh run
