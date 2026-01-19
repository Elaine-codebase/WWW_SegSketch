// Ethernet Header
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

// Ipv4 Header
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 4;
        ecn : 4;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}
header ipv4_t ipv4;

// TCP Header
header_type tcp_t {
    fields {
        srcPort : 16;
        dstDort : 16;
        seqNo: 32;
        ackNo: 32;
        dataOffset: 4;
        res: 4;
        flags: 8;
        window: 16;
        checksum: 16;
        urgentPtr: 16;
    }
}
header tcp_t tcp;

// UDP Header
header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        totalLen : 16;
        checksum : 16;
    }
}
header udp_t udp;

// User Custom Headers
header_type user_head_t {
    fields {
        // BL哈希结果
        dst_byte_1: 8;  // First Byte of Dst Addr
        dst_byte_2: 8;  // Second Byte of Dst Addr
        dst_byte_3: 8;  // Third Byte of Dst Addr
        dst_byte_4: 8;  // Fourth Byte of Dst Addr

        resubmit: 1;    // if resubmit
    }
}
header user_head_t user;

// Metadata
header_type metadata_t {
    fields {
        bl_hash_res1: 1;  // First Hash Res
        bl_hash_res2: 1;  // Second Hash Res
        bl_hash_res3: 1;  // Third Hash Res

        cell1_index: 2;   // the col index of first row
        cell2_index: 2;   // the col index of second row

        mask1: 8;         // the first mask
        mask2: 8;         // the second mask
        mask3: 8;         // the third mask

        resubmit: 1;      // 是否为重提交数据包
    }
}
metadata metadata_t mdata2;


header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

header_type vlan_tag_t {
    fields {
        pri     : 3;
        cfi     : 1;
        vlan_id : 12;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}
header ipv4_t ipv4;


header_type arp_t {
        fields {
                hardtype : 16;
                protocoltype : 16;
                idlebit : 16;
                op : 16;
                sendmac : 48;
                srcAddr : 32;
                dstmac : 48;
                dstAddr : 32;
        }
}
header arp_t arp;

header vlan_tag_t vlan;
header_type tcp_t {
    fields {
        srcport : 16;
        dstport : 16;
        seqNo: 32;
        ackNo: 32;
        dataOffset: 4;
        res: 4;
        flags: 8;
        window: 16;
        checksum: 16;
        urgentPtr: 16;
    }
}
header tcp_t tcp;

header_type udp_t {
    fields {
        srcport : 16;
        dstport : 16;
        totalLen : 16;
        checksum : 16;
    }
}
header udp_t udp;


header_type recir_header_t {
	fields {
		recir_num: 32;
	}
}
header recir_header_t recir_header;

