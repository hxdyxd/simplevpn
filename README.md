simplevpn
=========

simplevpn is a fast, safe VPN based on libsodium.

## Usage:

```
simplevpn 0.1.2

  usage:

    simplevpn

       -l <local_addr>            Your local udp address.
       -r <remote_addr>           Your remote server udp address.
       -L <local_addr>            Your local tcp address.
       -R <remote_addr>           Your remote server tcp address.
       [-t]                       Create tap device.
       -k <password>              Password of your remote server.
       -n <local_network>         Local network.
       -g <default_network>       Default network.
       -p <prefix>                Your network prefixs address.
       -d <cmd>                   Daemon start/stop/restart
       -e <log level>             0:never    1:fatal   2:error   3:warn
                                  4:info (default)     5:debug   6:trace

       [-v]                       Verbose mode.
       [-h, --help]               Print this message.
```

## Build simplevpn

```
sudo apt-get install pkg-config libsodium-dev
git clone --recursive https://github.com/hxdyxd/simplevpn.git
cd simplevpn
make -C ./src/ USE_CRYPTO=1
```
