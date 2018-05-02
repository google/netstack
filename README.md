# Netstack

Netstack is a network stack written in Go.

## Getting started

Try it out on Linux by installing the tun_tcp_echo demo:

```
go install github.com/google/netstack/tcpip/sample/tun_tcp_echo
```

Create a TUN device with:

```
[sudo] ip tuntap add user <username> mode tun <device-name>
[sudo] ip link set <device-name> up
[sudo] ip addr add <ipv4-address>/<mask-length> dev <device-name>
```

Then run with:

```
tun_tcp_echo <device-name> <ipv4-address> <port>
```

## Contributions

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

### Disclaimer

This is not an official Google product (experimental or otherwise), it
is just code that happens to be owned by Google.
