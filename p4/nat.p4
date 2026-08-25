#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<32> ETHERNET_HEADER_BYTES = 14;
const bit<8> IP_PROTOCOL_TCP = 6;
const bit<8> IP_PROTOCOL_UDP = 17;

const bit<2> ZONE_UNSET = 0;
const bit<2> ZONE_INSIDE = 1;
const bit<2> ZONE_OUTSIDE = 2;
const bit<2> ZONE_PUBLIC = 3;

const bit<16> IPV4_HEADER_BYTES = 20;
const bit<16> TCP_MIN_HEADER_BYTES = 20;
const bit<16> UDP_HEADER_BYTES = 8;

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

header transport_data_t {
    // Maximum data following fixed IPv4 and UDP headers.
    varbit<524056> data;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    transport_data_t transport_data;
}

struct metadata_t {
    bit<2> ingress_zone;
    bit<2> destination_zone;
    bit<1> route_ready;
    bit<1> nat_transport_valid;
    bit<1> udp_checksum_present;
    bit<16> transport_len;
    bit<16> udp_checksum_zero;
}

parser ParserImpl(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        meta.udp_checksum_present = 0;
        meta.udp_checksum_zero = 0;
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
        meta.transport_len = hdr.ipv4.total_len - IPV4_HEADER_BYTES;
        transition select(
            hdr.ipv4.ihl,
            hdr.ipv4.flags[0:0],
            hdr.ipv4.fragment_offset,
            hdr.ipv4.protocol) {
            (5, 0, 0, IP_PROTOCOL_TCP): parse_tcp;
            (5, 0, 0, IP_PROTOCOL_UDP): parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.total_len) {
            41 .. 0xffff: parse_tcp_data;
            default: accept;
        }
    }

    state parse_tcp_data {
        packet.extract(
            hdr.transport_data,
            (bit<32>) (meta.transport_len - TCP_MIN_HEADER_BYTES) << 3);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.checksum) {
            0: select_udp_data;
            default: mark_udp_checksum_present;
        }
    }

    state mark_udp_checksum_present {
        meta.udp_checksum_present = 1;
        transition select_udp_data;
    }

    state select_udp_data {
        transition select(hdr.ipv4.total_len) {
            29 .. 0xffff: parse_udp_data;
            default: accept;
        }
    }

    state parse_udp_data {
        packet.extract(
            hdr.transport_data,
            (bit<32>) (meta.transport_len - UDP_HEADER_BYTES) << 3);
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

        verify_checksum(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol,
                meta.transport_len,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.seq_no,
                hdr.tcp.ack_no,
                hdr.tcp.data_offset,
                hdr.tcp.reserved,
                hdr.tcp.ns,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgent_ptr,
                hdr.transport_data.data
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);

        verify_checksum(
            hdr.udp.isValid() && meta.udp_checksum_present == 1,
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol,
                hdr.udp.length,
                hdr.udp.src_port,
                hdr.udp.dst_port,
                hdr.udp.length,
                hdr.udp.checksum,
                hdr.transport_data.data
            },
            meta.udp_checksum_zero,
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

    action set_public_address(bit<32> public_addr) {
        hdr.ipv4.src_addr = public_addr;
    }

    action set_private_address(bit<32> private_addr) {
        hdr.ipv4.dst_addr = private_addr;
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

    table nat_outbound {
        key = {
            hdr.ipv4.src_addr: exact @name("private_addr");
        }
        actions = {
            set_public_address;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }

    table nat_inbound {
        key = {
            hdr.ipv4.dst_addr: exact @name("public_addr");
        }
        actions = {
            set_private_address;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }

    apply {
        meta.ingress_zone = ZONE_UNSET;
        meta.destination_zone = ZONE_OUTSIDE;
        meta.route_ready = 0;
        meta.nat_transport_valid = 0;

        if (hdr.ipv4.isValid() &&
            standard_metadata.parser_error == error.NoError &&
            standard_metadata.checksum_error == 0 &&
            hdr.ipv4.version == 4 &&
            hdr.ipv4.ihl == 5 &&
            hdr.ipv4.total_len >= IPV4_HEADER_BYTES &&
            (bit<32>) hdr.ipv4.total_len + ETHERNET_HEADER_BYTES <=
                standard_metadata.packet_length &&
            hdr.ipv4.flags[0:0] == 0 &&
            hdr.ipv4.fragment_offset == 0 &&
            hdr.ipv4.ttl > 1) {
            if (hdr.tcp.isValid() &&
                hdr.ipv4.total_len >=
                    IPV4_HEADER_BYTES + TCP_MIN_HEADER_BYTES &&
                hdr.tcp.data_offset >= 5 &&
                ((bit<16>) hdr.tcp.data_offset << 2) <=
                    meta.transport_len) {
                meta.nat_transport_valid = 1;
            } else if (hdr.udp.isValid() &&
                       hdr.ipv4.total_len >=
                           IPV4_HEADER_BYTES + UDP_HEADER_BYTES &&
                       hdr.udp.length >= UDP_HEADER_BYTES &&
                       hdr.udp.length == meta.transport_len) {
                meta.nat_transport_valid = 1;
            }

            if (zone_by_port.apply().hit) {
                destination_zone.apply();

                if (meta.ingress_zone == ZONE_INSIDE &&
                    meta.destination_zone == ZONE_INSIDE) {
                    meta.route_ready = 1;
                } else if (meta.ingress_zone == ZONE_INSIDE &&
                           meta.destination_zone == ZONE_OUTSIDE) {
                    if (meta.nat_transport_valid == 1 &&
                        nat_outbound.apply().hit) {
                        meta.route_ready = 1;
                    } else {
                        mark_to_drop(standard_metadata);
                    }
                } else if (meta.ingress_zone == ZONE_OUTSIDE &&
                           meta.destination_zone == ZONE_PUBLIC) {
                    if (meta.nat_transport_valid == 1 &&
                        nat_inbound.apply().hit) {
                        meta.route_ready = 1;
                    } else {
                        mark_to_drop(standard_metadata);
                    }
                } else {
                    mark_to_drop(standard_metadata);
                }

                if (meta.route_ready == 1 && !ipv4_lpm.apply().hit) {
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

        update_checksum(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol,
                meta.transport_len,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.seq_no,
                hdr.tcp.ack_no,
                hdr.tcp.data_offset,
                hdr.tcp.reserved,
                hdr.tcp.ns,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgent_ptr,
                hdr.transport_data.data
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);

        update_checksum(
            hdr.udp.isValid() && meta.udp_checksum_present == 1,
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                8w0,
                hdr.ipv4.protocol,
                hdr.udp.length,
                hdr.udp.src_port,
                hdr.udp.dst_port,
                hdr.udp.length,
                hdr.transport_data.data
            },
            hdr.udp.checksum,
            HashAlgorithm.csum16);

        update_checksum(
            hdr.udp.isValid() &&
                meta.udp_checksum_present == 1 &&
                hdr.udp.checksum == 0,
            // IPv4 UDP transmits a calculated zero as all ones.
            { 16w0 },
            hdr.udp.checksum,
            HashAlgorithm.csum16);
    }
}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.transport_data);
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
