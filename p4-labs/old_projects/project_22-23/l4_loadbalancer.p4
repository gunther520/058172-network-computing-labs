/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PORT_WIDTH 9

#define CLIENT_PORT_IDX 1
#define REG_NO_ENTRIES 1024
#define BACKEND1_IDX 2
#define BACKEND2_IDX 3
#define BACKEND3_IDX 4
#define BACKEND4_IDX 5

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* TODO 1: Define ethernet header */
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/* TODO 2: Define IPv4 header */
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
/* TODO 3: Define UDP header */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> pktLength;
    bit<16> checksum;
}

/* Metadata structure is used to pass information
 * across the actions, or the control block.
 * It is also used to pass information from the 
 * parser to the control blocks.
 */
struct metadata {
    bit<16> l4_payload_length;
    /* Used to understand if the packet belongs to a configured VIP */
    bit<1> pkt_is_virtual_ip;
    /* Used to keep track of the current backend assigned to a connection */
    bit<9> assigned_backend; //port
    /* TODO: Add here other metadata */
}

struct backenddata {
    bit<16> l4_payload_length;
    /* Used to understand if the packet belongs to a configured VIP */
    bit<16> no_of_flows;
}





struct headers {
    /* TODO 4: Define here the headers structure */
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv4_t ipv4_inner;
    udp_t udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        /* TODO 5: Parse Ethernet Header */
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4_outer;
  
            default: accept;
        }
    }

    state parse_ipv4_outer {
        packet.extract(hdr.ipv4);

        meta.l4_payload_length = hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) << 2);

        transition select(hdr.ipv4.protocol){
            TYPE_UDP:parse_udp;
            4:parse_ipv4;
            default: accept;
        }
        
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4_inner);
        /* This information is used to recalculate the checksum 
         * in the MyComputeChecksum control block.
         * Since we modify the udp header, we need to recompute the checksum.
         * We do it for you, so don't worry about it.
         */
        meta.l4_payload_length = hdr.ipv4_inner.totalLen - (((bit<16>)hdr.ipv4_inner.ihl) << 2);

        /* TODO 6: Define here the transition to the parse_udp state */
        transition select(hdr.ipv4_inner.protocol) {
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        /* TODO 7: Parse udp header */
        packet.extract(hdr.udp);
        transition accept;
        
    
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    

    /* Drop action */
    action drop() {
        mark_to_drop(standard_metadata);
        return;
    }

    /* Forward action */
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    /* This action is executed after a lookup on the vip_to_backend table */
    action update_backend_info(bit<32> ip, bit<16> port, bit<48> dstMac) {
        /* TODO 16: Update the packet fields before redirecting the 
         * packet to the backend.
         */
         hdr.ipv4_inner.setValid();
         hdr.ipv4_inner=hdr.ipv4;
         hdr.ipv4.protocol=4;
         hdr.ipv4.srcAddr=hdr.ipv4.dstAddr;
         hdr.ipv4.dstAddr=ip;
         hdr.ipv4.totalLen=hdr.ipv4.totalLen+20;
         //hdr.udp.srcPort=hdr.udp.dstPort;
         //hdr.udp.dstPort=port;
         hdr.ethernet.srcAddr=hdr.ethernet.dstAddr;
         hdr.ethernet.dstAddr=dstMac;
         


    }

    /* Define here all the other actions that you might need */

    /* This action is executed to check if the current packet is 
     * destined to a virtual IP configured on the load balancer.
     * This action is complete, you don't need to change it.
     */
    action is_virtual_ip(bit<1> val) {
        meta.pkt_is_virtual_ip = val;
    }

    /* This action is executed for packets coming from the backend servers.
     * You need to update the packet fields before redirecting the packet
     * to the client.
     * This action is executed after a lookup on the backend_to_vip table.
     */
    action backend_to_vip_conversion(bit<32> srcIP, bit<16> port, bit<48> srcMac) {
        /* TODO 18: Update the packet fields before redirecting the 
         * packet to the client. update the packet fields (IP, MAC, etc.)

         */

        hdr.ipv4.srcAddr=srcIP;
        hdr.ipv4.dstAddr=hdr.ipv4_inner.dstAddr;
        hdr.ipv4.protocol=TYPE_UDP;
        hdr.ipv4.totalLen=hdr.ipv4.totalLen-20;
        hdr.ipv4_inner.setInvalid();

        hdr.ethernet.srcAddr=srcMac;
        //how to get dstMac? by ARP?

        hdr.udp.srcPort=port;
        //dstPort is not important



    }

    /* Table used map a backend index with its information */
    table vip_to_backend {
        key = {
            meta.assigned_backend : exact;
        }
        actions = {
            update_backend_info;
            drop;
        }
        default_action = drop();
    }

    /* Table used to understand if the current packet is destined 
     * to a configured virtual IP 
     */
    table virtual_ip {
        key = {
            hdr.ipv4.dstAddr : exact;
            hdr.udp.dstPort : exact;
        }
        actions = {
            is_virtual_ip;
            drop;
        }
        default_action = drop();
    }

    /* Table used to map a backend with the information about the VIP */
    table backend_to_vip {
        key = {
            hdr.ipv4.srcAddr : lpm;
        }
        actions = {
            backend_to_vip_conversion;
            drop;
        }
        default_action = drop();
    }
    
    

    /* TODO 11: Define here the register where you keep information about
     * the backend assigned to a connection.
     */

    /* TODO 13: Define here the register where you keep information about
     * the number of connections assigned to a backend
     struct backenddata {
    bit<16> l4_payload_length;
    
    bit<16> no_of_flows;
}
     */
    register <bit<16>>(REG_NO_ENTRIES) reg_0; //store flow length
    register <bit<9>>(REG_NO_ENTRIES) reg_1; //store flow assigned backend
    register <bit<16>>(8) reg_2; //store backend Total payload
    register <bit<16>>(8) reg_3; //store backend numbers of flows

    apply {  
        /* TODO 8: Check if the ingress port is the one connected to the client. */
        if (standard_metadata.ingress_port==CLIENT_PORT_IDX){
        
        /* TODO 9: Verify whether the packet is destined for the Virtual IP 
         * If not, drop the packet.
         * If yes, continue with the ingress logic
         */
            virtual_ip.apply();
            if ( meta.pkt_is_virtual_ip==0){
                drop();
                return;
            };

            /* TODO 10: Check if the current connection is already assigned to a specific 
            * backend server. 
            * If yes, forward the packet to the assigned backend (but first check the FIN or RST flag).
            * If not, assign a new backend to the connection (only is the packet has the SYN flag set)
            * otherwise, drop the packet.
            */
            
            
            bit<32> output_hash_one;
            //need store state for that flow
            hash(output_hash_one, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,hdr.ipv4.dstAddr,hdr.udp.srcPort,hdr.udp.dstPort,hdr.ipv4.protocol}, (bit<32>)REG_NO_ENTRIES);
            bit<16> flowdata_length;
            bit<9> flowdata_backend;
            reg_0.read(flowdata_length,output_hash_one);
            reg_1.read(flowdata_backend,output_hash_one);

            if (flowdata_length==0){ //new flow
                //assign to backend server based on load
                bit<16> temp1_payload;
                bit<16> temp2_payload;
                bit<16> temp3_payload;
                bit<16> temp4_payload;

                bit<16> temp1_numbers;
                bit<16> temp2_numbers;
                bit<16> temp3_numbers;
                bit<16> temp4_numbers;
                reg_2.read(temp1_payload,BACKEND1_IDX);
                reg_2.read(temp2_payload,BACKEND2_IDX);
                reg_2.read(temp3_payload,BACKEND3_IDX);
                reg_2.read(temp4_payload,BACKEND4_IDX);

                reg_3.read(temp1_numbers,BACKEND1_IDX);
                reg_3.read(temp2_numbers,BACKEND2_IDX);
                reg_3.read(temp3_numbers,BACKEND3_IDX);
                reg_3.read(temp4_numbers,BACKEND4_IDX);

                bit<16> min_backend_payload;
                bit<16> min_backend_numbers;
                min_backend_payload=temp4_payload;
                min_backend_numbers=temp4_numbers;
                meta.assigned_backend=BACKEND4_IDX;

                

                if ((0==temp3_numbers && 0==temp3_payload)||(min_backend_payload*temp3_numbers>temp3_payload*min_backend_numbers)){
                    min_backend_payload=temp3_payload;
                    min_backend_numbers=temp3_numbers;
                    meta.assigned_backend=BACKEND3_IDX;
                }


                if ((0==temp2_numbers && 0==temp2_payload)||(min_backend_payload*temp2_numbers>temp2_payload*min_backend_numbers)){
                    min_backend_payload=temp2_payload;
                    min_backend_numbers=temp2_numbers;
                    meta.assigned_backend=BACKEND2_IDX;
                }

                if ((0==temp1_numbers && 0==temp1_payload)||(min_backend_payload*temp1_numbers>temp1_payload*min_backend_numbers)){
                    min_backend_payload=temp1_payload;
                    min_backend_numbers=temp1_numbers;
                    meta.assigned_backend=BACKEND1_IDX;
                }
                
                
                

                //update flow state
                
                flowdata_backend=meta.assigned_backend;
                flowdata_length=meta.l4_payload_length;

                reg_0.write(output_hash_one,flowdata_length);
                reg_1.write(output_hash_one,flowdata_backend);

                //update backend state
                min_backend_payload=min_backend_payload+meta.l4_payload_length;
                min_backend_numbers=min_backend_numbers+1;
                reg_2.write((bit<32>)meta.assigned_backend,min_backend_payload);
                reg_3.write((bit<32>)meta.assigned_backend,min_backend_numbers);





            }else{ //existing flow
                meta.assigned_backend=flowdata_backend;

                //update flow state
                flowdata_length=meta.l4_payload_length+flowdata_length;
                reg_0.write(output_hash_one,flowdata_length);

                //update backend state
                bit<16> temp1_payload;
                reg_2.read(temp1_payload,(bit<32>)meta.assigned_backend);
                


                temp1_payload=temp1_payload+meta.l4_payload_length;

                reg_2.write((bit<32>)meta.assigned_backend,temp1_payload);


            }
            vip_to_backend.apply();
            forward(meta.assigned_backend);
            


        }
        else{  //another direction
            backend_to_vip.apply();

            forward(1);
        }


        
        /* TODO 12: Define the logic to assign a new backend to the connection.
         * You should assign the backend with the minimum number of connections.
         * If there are multiple backends with the same number of connections,
         * you should assign the backend with the lowest index.
         */

        /* TODO 14: If the packet is already assigned, and if the FIN or RST flags are enabled 
         * you should remove the assignment and decrement the number of connections
         * for the backend. Finally, forward the packet to the backend.
        */

        /* TODO 15: Before redirecting the packet from CLIENT to BACKEND, make sure
         * to update the packet fields (IP, MAC, etc.).
         */

        /* TODO 17: If the packet is coming from the other direction, make sure
         * to update the packet fields (IP, MAC, etc.) before redirecting it
         * to the client. The backend_to_vip table is used to get the information
         * about the VIP.
         */
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        // Note: the following does not support tcp options.
        update_checksum_with_payload(
            hdr.udp.isValid() && hdr.ipv4.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4_payload_length,
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.pktLength
            },
            hdr.udp.checksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        
        packet.emit(hdr.ipv4_inner);
        
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;