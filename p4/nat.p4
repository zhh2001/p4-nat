#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> IP_PROTOCOL_TCP = 6;
const bit<8> IP_PROTOCOL_UDP = 17;

const bit<2> ZONE_UNSET = 0;
const bit<2> ZONE_INSIDE = 1;
const bit<2> ZONE_OUTSIDE = 2;

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragment_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<3> reserved;
    bit<1> ns;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct metadata_t {
    bit<2> ingress_zone;
    bit<2> destination_zone;
}

parser ParserImpl(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (5, IP_PROTOCOL_TCP): parse_tcp;
            (5, IP_PROTOCOL_UDP): parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control VerifyChecksumImpl(inout headers_t hdr, inout metadata_t meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid() && hdr.ipv4.ihl == 5,
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragment_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

control IngressImpl(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    action set_zone(bit<2> zone) {
        meta.ingress_zone = zone;
    }

    action set_destination_zone(bit<2> zone) {
        meta.destination_zone = zone;
    }

    action forward(bit<9> port, bit<48> src_mac, bit<48> dst_mac) {
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    table zone_by_port {
        key = {
            standard_metadata.ingress_port: exact @name("ingress_port");
        }
        actions = {
            set_zone;
            NoAction;
        }
        size = 3;
        default_action = NoAction();
    }

    table destination_zone {
        key = {
            hdr.ipv4.dst_addr: lpm @name("dst_addr");
        }
        actions = {
            set_destination_zone;
        }
        size = 16;
        default_action = set_destination_zone(ZONE_OUTSIDE);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm @name("dst_addr");
        }
        actions = {
            forward;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }

    apply {
        meta.ingress_zone = ZONE_UNSET;
        meta.destination_zone = ZONE_OUTSIDE;

        if (hdr.ipv4.isValid() &&
            standard_metadata.parser_error == error.NoError &&
            standard_metadata.checksum_error == 0 &&
            hdr.ipv4.version == 4 &&
            hdr.ipv4.ihl == 5 &&
            hdr.ipv4.ttl > 1) {
            if (zone_by_port.apply().hit) {
                destination_zone.apply();

                if (meta.ingress_zone == ZONE_INSIDE &&
                    meta.destination_zone == ZONE_INSIDE) {
                    if (!ipv4_lpm.apply().hit) {
                        mark_to_drop(standard_metadata);
                    }
                } else {
                    mark_to_drop(standard_metadata);
                }
            } else {
                mark_to_drop(standard_metadata);
            }
        } else {
            mark_to_drop(standard_metadata);
        }
    }
}

control EgressImpl(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    apply {
    }
}

control ComputeChecksumImpl(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid() && hdr.ipv4.ihl == 5,
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragment_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
