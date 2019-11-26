#!/bin/bash

cd /usr/local/tomcat && ./bin/startup.sh

echo "[+] Looking for tomcat PID..."

TOMCATPID=$(ps  | grep /usr/lib/jvm/java-1.8-openjdk/jre/bin/java | grep -o '[0-9]\+' | head -n 1)

re='^[0-9]+$'
if ! [[ $TOMCATPID =~ $re ]]; then
	echo "[-] Failed to find tomcat PID."
	echo "[-] Stopping execution."
	exit 1
fi

echo "[+] Found tomcat PID at ${TOMCATPID}."
echo "[+] Pausing for 10 seconds."
sleep 10


echo "[+] Attaching JMXMP Agent to tomcat instance..."
java -jar /opt/JMXMPAgent/agent/target/helios-jmxmp-agent-1.0-SNAPSHOT.jar -install $TOMCATPID 8888:0.0.0.0:DefaultDomain

echo "[+] Finished container startup."
echo "[+] Reading logs..."
tail -f logs/catalina.out
