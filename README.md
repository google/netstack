> NOTE: This repository is no longer maintained. The Netstack code will continue
> to be updated and maintained as part of
> [gVisor](http://www.github.com/google/gvisor/tree/go), which now also
> maintains a branch that is useable with standard Go tools.

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

## Issues/Bug Reports

Netstack is primarily developed as part of
[gVisor](http://www.github.com/google/gvisor) and any issues/bugs should be
filed against the gVisor repository as this repo is not actively monitored for
bug reports.

### Disclaimer

This is not an official Google product (experimental or otherwise), it is just
code that happens to be owned by Google.
