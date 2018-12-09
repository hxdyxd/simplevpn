#!/bin/bash

PHY_DEV="ens33"
TAP_DEV="tap0"

TAP_MTU="1400"
SERVER_IP="127.0.0.1"
SERVER_PORT="2020"
SERVER_KEY="12345678"

PHY_REALY_GW="10.9.0.1"
PHY_REALY_NETMASK="255.255.255.0"
PHY_REALY_NET="10.9.0.0/24"


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

killall -9 simplevpn-client
./simplevpn-client -s $SERVER_IP -p $SERVER_PORT -k $SERVER_KEY &

sleep 1
ifconfig $TAP_DEV mtu $TAP_MTU

# killall -9 udhcpc
PID_UDHCPC=`ps -ef | grep udhcpc | grep ${TAP_DEV} | awk '{print $2}'`
if [ -n "$PID_UDHCPC" ]; then
	echo "pid of udhcpc: "${PID_UDHCPC}
	kill -9 $PID_UDHCPC
fi
udhcpc -i $TAP_DEV

# route add default gw 10.10.0.1

PHY_GW=`ip route | grep via | grep default | grep ${PHY_DEV} | awk '{print $3}'`
if [ -n "$PHY_GW" ]; then
	ip route del default gw $PHY_GW
	ip route add $SERVER_IP via $PHY_GW
	echo "delete your default gateway: "${PHY_GW}
fi
if [ -z "$PHY_GW" ]; then 
	byellow "[warn] not found default gateway of "${PHY_DEV}
fi

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 1 > /proc/sys/net/ipv6/conf/default/forwarding

ifconfig $PHY_DEV:1 $PHY_REALY_GW netmask $PHY_REALY_NETMASK up

iptables -t nat -F POSTROUTING
iptables -F FORWARD

iptables -P FORWARD ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s $PHY_REALY_NET -o $TAP_DEV -j MASQUERADE

iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "your remote server: "${SERVER_IP}":"${SERVER_PORT}
echo "your local gw server: "${PHY_REALY_GW}

green "$0 done"
