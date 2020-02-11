#!/bin/bash

# It is a clear IPSec-IKEv2, work on all possible platforms!!!
# Need root priv.
# Created with this guide https://krasovsky.me/it/2016/08/strongswan-ikev2/
# modified by Mihas
# don't forget to open port in firewall http/80 udp/4500 and udp/500
# issue - don't wotk in Windows 10
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

domain_name=''
while [ "$domain_name" = "" ]; do
    echo -n "Enter domain name VPN, or ip_address (example: strongswan.tk): "
    read domain_name

#host_ip=$(curl --ipv4 icanhazip.com)
#host_name=strongswan.tk

apt-get update -y
apt-get install -y strongswan libcharon-extra-plugins dnsmasq
 
# Let's Encrypt загружаем из jessie-backports (Debian or from Ubuntu)
#sudo apt-get install -t jessie-backports letsencrypt
apt-get install -y letsencrypt

letsencrypt certonly --standalone --email jackalldroid@gmail.com -d $domain_name --rsa-key-size 4096

cp /etc/letsencrypt/live/$domain_name/fullchain.pem /etc/ipsec.d/certs
cp /etc/letsencrypt/live/$domain_name/privkey.pem /etc/ipsec.d/private
wget -O /etc/ipsec.d/cacerts/lets-encrypt-x3-cross-signed.pem https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem

#Configure StrongSwan
mv /etc/ipsec.conf /etc/ipsec.conf.bak
cat <<EOT > /etc/ipsec.conf
config setup
	# Раскомментируйте, если хотите несколько подключений на один логин
	uniqueids=never	

conn %default
	dpdaction=clear
	dpddelay=35s
	dpdtimeout=300s

	fragmentation=yes
	rekey=no

	left=%any
	leftsubnet=0.0.0.0/0
	leftcert=fullchain.pem
	leftfirewall=yes
	leftsendcert=always

	right=%any
	rightsourceip=192.168.103.0/24
	rightdns=8.8.8.8,8.8.4.4

	eap_identity=%identity

# IKEv2
conn IPSec-IKEv2
	keyexchange=ikev2
	auto=add

# BlackBerry, Windows, Android
conn IPSec-IKEv2-EAP
	also="IPSec-IKEv2"
	rightauth=eap-mschapv2

# macOS, iOS
conn IKEv2-MSCHAPv2-Apple
	also="IPSec-IKEv2"
	rightauth=eap-mschapv2
	leftid=$domain_name

# Android IPsec Hybrid RSA
conn IKEv1-Xauth
	keyexchange=ikev1
	rightauth=xauth
	auto=add

#include /var/lib/strongswan/ipsec.conf.inc
EOT

# Enable forwarding in Sysctl.conf
cp /etc/sysctl.conf /etc/sysctl.conf.bak
#sed -ir 's/#{1,}?net.ipv4.ip_forward ?= ?(0|1)/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf
#sed -ir 's/#{1,}?net.ipv6.conf.all.forwarding ?= ?(0|1)/net.ipv6.conf.all.forwarding = 1/g' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

cat <<EOT >> /etc/ipsec.secrets
: RSA privkey.pem
pozuser : EAP "pozitiff"
user2 : XAUTH "password"
"Windows Phone\user3" : EAP "password3"
EOT

#we'll tell IPTables to forward ESP (Encapsulating Security Payload) traffic so the VPN clients will be able to connect. ESP provides additional security for our VPN packets as they're traversing untrusted networks:
#sudo iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s 192.168.103.0/24 -j ACCEPT
#sudo iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d 192.168.103.0/24 -j ACCEPT

#Our VPN server will act as a gateway between the VPN clients and the internet. Since the VPN server will only have a single public IP #address, we will need to configure masquerading to allow the server to request data from the internet on behalf of the clients; this #will allow traffic to flow from the VPN clients to the internet, and vice-versa:
iptables -t nat -A POSTROUTING -s 192.168.103.0/24 -o eth0 -m policy --dir out --pol ipsec -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.103.0/24 -o eth0 -j MASQUERADE

# Настройка MTU для Android IKEv1
iptables -t mangle -I FORWARD -p tcp -m policy --pol ipsec --dir in --syn -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
iptables -t mangle -I FORWARD -p tcp -m policy --pol ipsec --dir out --syn -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

apt-get install iptables-persistent -y

#for split tunneling
cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
cat <<EOT > /etc/dnsmasq.conf
dhcp-vendorclass=set:msipsec,MSFT 5.0
dhcp-range=tag:msipsec,192.168.103.0,static
dhcp-option=tag:msipsec,6
dhcp-option=tag:msipsec,249, 0.0.0.0/1,0.0.0.0, 128.0.0.0/1,0.0.0.0
EOT

ipsec restart
systemctl restart dnsmasq

#Failed to restart networking.service: Unit networking.service not found.
#systemctl restart networking

#При желании можно писать системные логи в /dev/null (так себе идея):
#sudo rm /var/log/syslog && sudo ln -s /dev/null /var/log/syslog
#sudo rm /var/log/auth.log && sudo ln -s /dev/null /var/log/auth.log
ipsec listcerts
done
exit $?
