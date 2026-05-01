# p2p

Collection of programs to facilitate p2p communication. For the time being there is only a STUN program which fetches your NAT mapping from private IP:Port to public IP:Port.

## Quick Guide

1. NAT Mapping
```shell
cc -Wall -Wextra -o stun stun.c && ./stun 8080
```
You may replace the port number with any port you wish to check the NAT mapping for.

2. P2P UDP communication
```shell
cc -Wall -Wextra -o peer peer.c
./peer 9090 # If prompted, enter the Public IP of the peer you want to communicate with.
```
