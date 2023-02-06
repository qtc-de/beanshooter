#!/bin/sh

IP=$(cat /etc/hosts | tail -n 1 | cut -f1 -d"	")
echo "[+] IP address of the container: ${IP}" 

echo "[+] Adding gateway address to /etc/hosts file..."
GATEWAY="$(echo ${IP} | cut -f4 -d. --complement).1"
echo "${GATEWAY} prevent.reverse.dns" >> /etc/hosts

echo "[+] Starting tomcat..."
exec catalina.sh run
