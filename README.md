# P4 static IPv4 NAT

This project is a minimal static 1:1 IPv4 NAT for the BMv2 `simple_switch_grpc` target. Address translation, TTL handling, and IPv4/TCP/UDP checksum updates all run in the P4 data plane. A small Go controller installs the pipeline and static P4Runtime entries.

TCP and UDP ports are never translated. This is not PAT or NAPT.

## Topology

```text
                    INSIDE                         OUTSIDE

 h1 10.0.1.1/24 ---- port 1 ---+
                               +--- s1 --- port 3 ---- h3 10.0.3.1/24
 h2 10.0.2.1/24 ---- port 2 ---+
```

Ports 1 and 2 are `INSIDE`; port 3 is `OUTSIDE`. The links use deterministic host and switch-facing MAC addresses. Mininet configures static routes, permanent neighbor entries, and disabled interface offloads, so ARP and checksum offload do not obscure packet behavior.

The public addresses use the `192.0.2.0/24` documentation prefix. They are routed identities and are not assigned to host interfaces:

| Private address | Public address |
| --- | --- |
| `10.0.1.1` | `192.0.2.1` |
| `10.0.2.1` | `192.0.2.2` |

The outside host routes `192.0.2.0/24` toward the switch.

## Pipeline

```text
parse -> verify -> classify -> NAT -> IPv4 route -> TTL/MAC rewrite
      -> recompute checksums -> deparse
```

The parser accepts Ethernet followed by fixed-header IPv4 and parses TCP or UDP for unfragmented packets. Ingress processing validates the IPv4 version, header length, total length, incoming checksum, fragment fields, and TTL. Parsed TCP and non-zero-checksum UDP packets also require valid incoming transport checksums. NAT paths additionally require a valid TCP data offset or a UDP length matching the IPv4 payload length. Transport checksum input is bounded by IPv4 `total_len`; trailing Ethernet padding is preserved but excluded from the calculation.

Direction comes from the P4Runtime-programmed ingress zone and destination zone:

- `INSIDE -> OUTSIDE`: exact-match `nat_outbound` rewrites the private source address to its public address. A missing mapping is dropped.
- `OUTSIDE -> public prefix`: exact-match `nat_inbound` rewrites the public destination address to its private address. A missing mapping is dropped.
- `INSIDE -> INSIDE`: the packet is routed without address translation.
- Other zone combinations are dropped.

IPv4 route lookup occurs after translation. Inbound traffic is therefore routed on the translated private destination, while outbound routing continues to use the original destination. A route miss is dropped. The forwarding action rewrites both Ethernet addresses and decrements TTL exactly once; packets with TTL 0 or 1 are dropped before subtraction.

The egress checksum control recomputes the IPv4 header checksum and the TCP or UDP checksum over the translated IPv4 pseudo-header. For IPv4 UDP, an incoming checksum of zero means checksum-disabled and remains zero. A supplied UDP checksum is recalculated and encoded as `0xffff` when the one's-complement result is zero.

## P4Runtime controller

The controller uses [`p4runtime-go-controller`](https://github.com/zhh2001/p4runtime-go-controller) to connect to BMv2, become primary, install and read back the pipeline, insert the zone, route, and two-way static NAT entries, then read back and compare all 13 table entries exactly.

With the switch running, `--verify-only` checks the installed pipeline and table state without installing or writing anything:

```sh
build/p4natctl --verify-only
```

The default address is `127.0.0.1:9559`, device ID is 1, and artifacts are read from `build/`. Other values can be supplied through the controller flags.

## Prerequisites

- Linux with root access for Mininet
- P4 compiler with the BMv2 v1model backend (`p4c-bm2-ss`)
- BMv2 `simple_switch_grpc`
- Mininet, `iproute2`, and `ethtool`
- Python 3, Scapy, and tcpdump
- Go as specified by `go.mod`
- GNU Make

The project uses the installed P4 toolchain directly and does not require Docker.

## Build and run

```sh
make build
make run
```

`make build` compiles `p4/nat.p4` with warnings treated as errors and builds the Go controller. Generated P4Info, BMv2 JSON, controller binaries, and test bytecode remain under ignored `build/`.

`make run` starts BMv2, configures all P4Runtime entries, and opens an interactive Mininet CLI. For example:

```text
mininet> net
mininet> h1 ip route
mininet> h3 ip route
```

Exiting the CLI stops the owned switch process, removes its interfaces, and deletes the temporary runtime directory.

## Test and clean

```sh
make test
make clean
```

`make test` builds from source, runs Go tests and `go vet`, compiles the Python sources, inspects the generated P4Info and BMv2 JSON, and starts the complete Mininet topology. The automated suite verifies:

- both static mappings in both directions;
- TCP and UDP address translation with unchanged ports and payload;
- independent IPv4, TCP, and UDP checksum validity;
- non-zero Ethernet padding outside IPv4 `total_len`;
- IPv4 UDP zero-checksum preservation and the `0xffff` encoding edge case;
- a real TCP request/response whose outside server sees peer `192.0.2.1`;
- Ethernet rewriting, one-hop TTL behavior, isolation, and packet multiplicity;
- inside-to-inside forwarding without NAT;
- mapping and route misses, invalid checksums, exhausted TTL, options, fragments, unsupported NAT protocols, and malformed TCP/UDP lengths;
- cleanup after both successful operation and intentional startup failure.

Tests and `make run` invoke `sudo` for Mininet. `make clean` removes only project-generated build and Python cache directories.

## Limitations

This is static 1:1 IPv4 NAT. It has no PAT/NAPT, port translation, dynamic pools, dynamic port allocation, connection tracking, state timeouts, hairpin NAT, twice NAT, policy NAT, firewall state, dynamic routing, IPv6, or ALG support.

IPv4 options are unsupported (`IHL` must be 5). All IPv4 fragments, including first fragments with `MF=1`, are dropped. Address translation supports only TCP and UDP; other IPv4 protocols are dropped when a NAT mapping would be required. ICMP NAT and ICMP error-message translation are not implemented. ARP is handled by static host configuration rather than the P4 program.

This repository is a reference implementation, not a production NAT gateway.

## License

Apache License 2.0. See `LICENSE`.
