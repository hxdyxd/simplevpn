#!/bin/bash

PHY_DEV="eth0"
TAP_DEV="tap0"
TAP_MTU="1400"
TAP_IP="10.10.0.1"
TAP_NET="10.10.0.0/24"

SERVER_IP="127.0.0.1"
SERVER_PORT="2020"
SERVER_KEY="12345678"

## green to echo 
function green(){
    echo -e "\033[32m$1 \033[0m"
}

## Error
function bred(){
    echo -e "\033[31m\033[01m$1 \033[0m"
}

## warning
function byellow(){
    echo -e "\033[33m\033[01m$1 \033[0m"
}


echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

killall -9 simplevpn-client
./simplevpn-client -s $SERVER_IP -p $SERVER_PORT -k $SERVER_KEY &

sleep 1

ifconfig $TAP_DEV $TAP_IP netmask 255.255.255.0
ifconfig $TAP_DEV mtu $TAP_MTU

iptables -t nat -F POSTROUTING

iptables -P FORWARD ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s $TAP_NET -o $PHY_DEV -j MASQUERADE

iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "your remote server: "${SERVER_IP}":"${SERVER_PORT}

udhcpd ./tap-udhcpd.conf&

green $0 done
