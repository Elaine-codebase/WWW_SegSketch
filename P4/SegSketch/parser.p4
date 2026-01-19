#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define IPV4_TCP 0x06
#define IPV4_UDP 0x11

// 解析
parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol){
        IPV4_TCP: parse_tcp;
        IPV4_UDP: parse_udp;
        default: ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    return parse_custom_header;
}

parser parse_udp {
    extract(udp);
    return parse_custom_header;
}

parser parse_custom_header {
    extract(user);
    return ingress;
}
