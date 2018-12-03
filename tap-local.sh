#!/bin/bash

PHY_DEV="ens33"
TAP_DEV="tap0"

TAP_MTU="1400"
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
	route del default gw $PHY_GW
	route add -host $SERVER_IP gw $PHY_GW
	echo "delete your default gateway: "${PHY_GW}
fi
if [ -z "$PHY_GW" ]; then 
	byellow "[warn] not found default gateway of "${PHY_DEV}
fi

echo "your remote server: "${SERVER_IP}":"${SERVER_PORT}

green "$0 done"
