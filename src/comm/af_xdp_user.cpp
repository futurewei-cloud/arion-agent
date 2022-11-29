//
// Created by ubuntu on 10/4/22.
//
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <linux/udp.h>
//#include <linux/if_arp.h>
#include <assert.h>
#include <poll.h>
#include <db_client.h>
//#include <grpc_client.h>
#include "af_xdp_user.h"
#include <sys/resource.h>
#include <signal.h>
#include <cstdlib>
#include <unistd.h>
#include <bpf.h>
#include <cerrno>
#include <sys/poll.h>
#include <csignal>
#include <cstring>
#include <string>
#include <bpf_endian.h>
#include "xdp/trn_datamodel.h"
#include "util.h"
//#include "xdp/trn_kern.h"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX
#define MSG_DONTWAIT	= 0x40
#define VXL_DSTPORT 0xb512 // UDP dport 4789(0x12b5) for VxLAN overlay
/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	2		/* ARP reply			*/
#ifndef PATH_MAX

#define PATH_MAX	4096
#endif

struct vxlanhdr_internal {
    /* Big endian! */
    __u8 rsvd1 : 3;
    __u8 i_flag : 1;
    __u8 rsvd2 : 4;
    __u8 rsvd3[3];
    __u8 vni[3];
    __u8 rsvd4;
};


///*
// *	This structure defines an ethernet arp header.
// */
//
//struct arphdr {
//    __be16		ar_hrd;		/* format of hardware address	*/
//    __be16		ar_pro;		/* format of protocol address	*/
//    unsigned char	ar_hln;		/* length of hardware address	*/
//    unsigned char	ar_pln;		/* length of protocol address	*/
//    __be16		ar_op;		/* ARP opcode (command)		*/
//
//#if 0
//	 /*
//	  *	 Ethernet looks like this : This bit is variable sized however...
//	  */
//	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
//	unsigned char		ar_sip[4];		/* sender IP address		*/
//	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
//	unsigned char		ar_tip[4];		/* target IP address		*/
//#endif
//
//};

struct arp_message {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
} __attribute__((__packed__));

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct stats_record {
    uint64_t timestamp;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;

    uint32_t outstanding_tx;

    struct stats_record stats;
    struct stats_record prev_stats;
};

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{

    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
                                                    struct xsk_umem_info *umem)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    /* TODO: Fill in the prog_id of the 'transit' xdp program
        otherwise, the xsk_socket__create will create a map with the name 'xsk_map'
     */
    uint32_t prog_id = 0;
    int i;
    int ret;

    xsk_info = static_cast<xsk_socket_info *>(calloc(1, sizeof(*xsk_info)));
    if (!xsk_info)
        return static_cast<xsk_socket_info *>(nullptr);

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.xdp_flags = cfg->xdp_flags;
    xsk_cfg.bind_flags = cfg->xsk_bind_flags;
    if (!umem->umem) {
        printf("%s\n", "umem is empty!");
    }
    if (!(&xsk_info->xsk)) {
        printf("%s\n", "xsk_ptr is empty!");
    }
    if (!(&xsk_info->tx)) {
        printf("%s\n", "tx is empty!");
    }
    if (!(&xsk_info->rx)) {
        printf("%s\n", "rx is empty!");
    }
    ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
                             cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
                             &xsk_info->tx, &xsk_cfg);

    if (ret) {
        printf("xsk_socket__create failed with ret: [%ld]\n", ret);
        goto error_exit;
    }

    ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
    if (ret) {
        printf("bpf_get_link_xdp_id failed\n");
        goto error_exit;
    }

    /* Initialize umem frame allocation */

    for (i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    /* Stuff the receive path with buffers, we assume we have enough */
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                 &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        printf("xsk_ring_prod__reserve failed\n");
        goto error_exit;
    }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
                xsk_alloc_umem_frame(xsk_info);

    xsk_ring_prod__submit(&xsk_info->umem->fq,
                          XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

error_exit:
    errno = -ret;
    return static_cast<xsk_socket_info *>(nullptr);
}

static const struct option_wrapper long_options[] = {

    {{"help",	 no_argument, nullptr, 'h' },
      "Show help", "",false},

    {{"dev",	 required_argument,	nullptr, 'd' },
      "Operate on device <ifname>", "<ifname>", true},

    {{"skb-mode",	 no_argument, nullptr, 'S' },
      "Install XDP program in SKB (AKA generic) mode"},

    {{"native-mode", no_argument, nullptr, 'N' },
      "Install XDP program in native mode"},

    {{"auto-mode",	 no_argument,		nullptr, 'A' },
      "Auto-detect SKB or native mode"},

    {{"force",	 no_argument,		nullptr, 'F' },
      "Force install, replacing existing program on interface"},

    {{"copy",        no_argument,		nullptr, 'c' },
      "Force copy mode"},

    {{"zero-copy",	 no_argument,		nullptr, 'z' },
      "Force zero-copy mode"},

    {{"queue",	 required_argument,	nullptr, 'Q' },
      "Configure interface receive queue for AF_XDP, default=0"},

    {{"poll-mode",	 no_argument,		nullptr, 'p' },
      "Use the poll() API waiting for packets to arrive"},

    {{"unload",      no_argument,		nullptr, 'U' },
      "Unload XDP program instead of loading"},

    {{"quiet",	 no_argument,		nullptr, 'q' },
      "Quiet mode (no output)"},

    {{"filename",    required_argument,	nullptr,  1  },
      "Load program from <file>", "<file>"},

    {{"progsec",	 required_argument,	nullptr,  2  },
      "Load program in <section> of the ELF file", "<section>"},

    {{0, 0, nullptr,  0 }, nullptr, "",false}
};

static bool global_exit;

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk->outstanding_tx)
        return;

    sendto(xsk_socket__fd(xsk->xsk), NULL, 0, 0X40/*MSG_DONTWAIT*/, NULL, 0);


    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek(&xsk->umem->cq,
                                    XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                    &idx_cq);

    if (completed > 0) {
        for (int i = 0; i < completed; i++)
            xsk_free_umem_frame(xsk,
                                *xsk_ring_cons__comp_addr(&xsk->umem->cq,
                                                          idx_cq++));

        xsk_ring_cons__release(&xsk->umem->cq, completed);
        xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
                                       completed : xsk->outstanding_tx;
    }
}



static bool process_packet(struct xsk_socket_info *xsk,
                           uint64_t addr, uint32_t len, int* fd)
{
//    printf(">>>>>>>>>>  Begin processing packet  >>>>>>>>>>\n");
    uint8_t *pkt = static_cast<uint8_t *>(xsk_umem__get_data(xsk->umem->buffer, addr));


    if (true) {
        /*
         * TODO: Parse packet here, get VNI, IP, MAC, lookup locally in DB, and replace neigbor host IP if found;
         * if NOT found, drop packet and remotely GET from Arion Master.
         * */
        int ret;
        uint32_t tx_idx = 0;
        uint8_t tmp_mac[ETH_ALEN];
        // parse outer eth header
        struct ethhdr *eth = (struct ethhdr *) pkt;

        if (ntohs(eth->h_proto) != ETH_P_IP) {
//            printf("%s\n", "returning false for this packet as it is NOT IP");
            return false;
        }
//        printf("Packet length: %ld\n", len);
//        printf("Outer eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n"
//               "eth size: %d\n",
//               eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5],
//               eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5],
//               bpf_ntohs(eth->h_proto),
//               sizeof(*eth));

        // parse outer IP header
        struct iphdr *ip = (struct iphdr *) (eth + 1/*sizeof(*eth)*/);
        struct in_addr outer_ip_src;
        outer_ip_src.s_addr = ip->saddr;
        struct in_addr outer_ip_dest;
        outer_ip_dest.s_addr = ip->daddr;
//        printf("Outer ip src: %s, ip dest: %s\n"
//               "Outer ip ihl: %d, version: %d\n",
//                inet_ntoa(outer_ip_src),inet_ntoa(outer_ip_dest),
//                ip->ihl, ip->version);

        // parse UDP header
        struct udphdr *udp = (struct udphdr *) (ip + 1/*sizeof(*ip)*/);
//        printf("UDP dest: %d, UDP src: %d, == VXL_DSTPORT? %s\n",
//               udp->dest, udp->source, (udp->dest==VXL_DSTPORT? "true" : "false"));

        // parse VXLAN header
        struct vxlanhdr_internal* vxlan = (struct vxlanhdr_internal *)(udp + 1/*sizeof(*udp)*/);
//        printf("VNI: %ld, \n",trn_get_vni(vxlan->vni));

        // parse inner eth header
        struct ethhdr *inner_eth = (struct ethhdr *)(vxlan + 1/*sizeof(*vxlan)*/);
//        printf("inner eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n",
//               inner_eth->h_source[0],inner_eth->h_source[1],inner_eth->h_source[2],inner_eth->h_source[3],inner_eth->h_source[4],inner_eth->h_source[5],
//               inner_eth->h_dest[0],inner_eth->h_dest[1],inner_eth->h_dest[2],inner_eth->h_dest[3],inner_eth->h_dest[4],inner_eth->h_dest[5],
//               inner_eth->h_proto);

        if (ntohs(inner_eth->h_proto) == ETH_P_ARP) {
            // parse inner arp header
            arp_message *arp_msg = (struct arp_message *)(inner_eth + 1);
            struct in_addr arp_src_ip;
            arp_src_ip.s_addr = arp_msg->spa;
            struct in_addr arp_dest_ip;
            arp_dest_ip.s_addr = arp_msg->tpa;
//            printf("arp op: %d\n",
//                   bpf_htons(arp_msg->op));
//            printf("arp source ip: %s, \n",
//                   inet_ntoa(arp_src_ip/*inner_arp_dest_ip*/)
//            );
//            printf("arp dest ip: %s, \n",
//                   inet_ntoa(arp_dest_ip/*inner_arp_dest_ip*/)
//            );
            endpoint_key_t epkey;
            epkey.vni = trn_get_vni(vxlan->vni);
            struct sockaddr_in ep_ip;
            inet_pton(AF_INET, inet_ntoa(arp_dest_ip/*inner_arp_dest_ip*/), &(ep_ip.sin_addr));
            epkey.ip = ep_ip.sin_addr.s_addr;
            auto ep_value = db_client::get_instance().GetNeighborInMemory(&epkey);
//            endpoint_t ep_value;
//            ep_value = db_client::get_instance().GetNeighbor(trn_get_vni(vxlan->vni), inet_ntoa(arp_dest_ip));
            if (ep_value != nullptr) {
                // we now have key and value, can modify the packet and update the map now.
//                int ebpf_rc = bpf_map_update_elem((*fd), &epkey, &ep_value, BPF_ANY);
//                printf("AF_XDP: Inserted this neighbor into map: vip: %s, vni: %d, ebpf_rc: %d\n",
//                       inet_ntoa(arp_src_ip), trn_get_vni(vxlan->vni), 0);

                /* Modify pkt for inner ARP response */
                arp_msg->op = bpf_htons(ARPOP_REPLY);
                trn_set_mac(arp_msg->tha, arp_msg->sha);
                trn_set_mac(arp_msg->sha, ep_value->mac);

                __u32 tmp_ip = arp_msg->spa;//*sip;
                arp_msg->spa = arp_msg->tpa;//*tip;
                arp_msg->tpa = tmp_ip;

                /* Modify inner EitherHdr, pretend it's from target */
                trn_set_dst_mac(inner_eth, inner_eth->h_source);
                trn_set_src_mac(inner_eth, ep_value->mac);

                /* Keep overlay header, swap outer IP header */
                trn_set_src_dst_ip_csum(ip, ip->daddr, ip->saddr, (eth + len));
                trn_swap_src_dst_mac(pkt);

                /*
             * Packet modification finished, read packet content again, in order to verify the mod
             * */

                struct ethhdr *eth = (struct ethhdr *) pkt;

                if (ntohs(eth->h_proto) != ETH_P_IP) {
//                    printf("%s\n", "AFTER MOD: returning false for this packet as it is NOT IP");
                    return false;
                }
//                printf("AFTER MOD: Packet length: %ld\n", len);
//                printf("AFTER MOD: Outer eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n"
//                       "eth size: %d\n",
//                       eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5],
//                       eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5],
//                       bpf_ntohs(eth->h_proto),
//                       sizeof(*eth));
//
//                // parse outer IP header
//                struct iphdr *ip = (struct iphdr *) (eth + 1/*sizeof(*eth)*/);
//                struct in_addr outer_ip_src;
//                outer_ip_src.s_addr = ip->saddr;
//                struct in_addr outer_ip_dest;
//                outer_ip_dest.s_addr = ip->daddr;
//                printf("AFTER MOD: Outer ip src: %s, ip dest: %s\n"
//                       "AFTER MOD: Outer ip ihl: %d, version: %d\n",
//                       inet_ntoa(outer_ip_src),inet_ntoa(outer_ip_dest),
//                       ip->ihl, ip->version);
//
//                // parse UDP header
//                struct udphdr *udp = (struct udphdr *) (ip + 1/*sizeof(*ip)*/);
//                printf("AFTER MOD: UDP dest: %d, UDP src: %d, == VXL_DSTPORT? %s\n",
//                       udp->dest, udp->source, (udp->dest==VXL_DSTPORT? "true" : "false"));
//
//                // parse VXLAN header
//                struct vxlanhdr_internal* vxlan = (struct vxlanhdr_internal *)(udp + 1/*sizeof(*udp)*/);
//                printf("AFTER MOD: VNI: %ld, \n",trn_get_vni(vxlan->vni));
//
//                // parse inner eth header
//                struct ethhdr *inner_eth = (struct ethhdr *)(vxlan + 1/*sizeof(*vxlan)*/);
//                printf("AFTER MOD: inner eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n",
//                       inner_eth->h_source[0],inner_eth->h_source[1],inner_eth->h_source[2],inner_eth->h_source[3],inner_eth->h_source[4],inner_eth->h_source[5],
//                       inner_eth->h_dest[0],inner_eth->h_dest[1],inner_eth->h_dest[2],inner_eth->h_dest[3],inner_eth->h_dest[4],inner_eth->h_dest[5],
//                       inner_eth->h_proto);
//
//                // parse inner arp header
//                arp_message *arp_msg = (struct arp_message *)(inner_eth + 1);
//                struct in_addr arp_src_ip;
//                arp_src_ip.s_addr = arp_msg->spa;
//                struct in_addr arp_dest_ip;
//                arp_dest_ip.s_addr = arp_msg->tpa;
//                printf("AFTER MOD: arp op: %d\n",
//                       bpf_htons(arp_msg->op));
//                printf("AFTER MOD: arp source ip: %s, \n",
//                       inet_ntoa(arp_src_ip/*inner_arp_dest_ip*/)
//                );
//                printf("AFTER MOD: arp dest ip: %s, \n",
//                       inet_ntoa(arp_dest_ip/*inner_arp_dest_ip*/)
//                );
                /* Here we sent the packet out of the receive port. Note that
		 * we allocate one entry and schedule it. Your design would be
		 * faster if you do batch processing/transmission */

                ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
                if (ret != 1) {
                    /* No more transmit slots, drop the packet */
                    return false;
                }

                xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
                xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
                xsk_ring_prod__submit(&xsk->tx, 1);
                xsk->outstanding_tx++;

                xsk->stats.tx_bytes += len;
                xsk->stats.tx_packets++;
//                printf("Packet sent via tx queue\n");
//                printf("<<<<<<<<<<  Finished processing packet  <<<<<<<<<<\n");

                return true;
            } else {
                printf("Can't find endpoint!\n");
                return false;
            }
        }else if (ntohs(inner_eth->h_proto) == ETH_P_IP) {
            // TODO: Add inner IP support, refer to trn_process_inner_ip
            // parse inner IP header
            struct iphdr *inner_ip = (struct iphdr *)(inner_eth + 1 /*sizeof(*inner_eth)*/);
            struct in_addr inner_ip_src, inner_ip_dest;
            inner_ip_src.s_addr = inner_ip->saddr;
            inner_ip_dest.s_addr = inner_ip->daddr;
//            printf("Inner IP src: %s\n", inet_ntoa(inner_ip_src));
//            printf("Inner IP dest: %s\n", inet_ntoa(inner_ip_dest));
            endpoint_key_t epkey;
            epkey.vni = trn_get_vni(vxlan->vni);
            struct sockaddr_in ep_ip;
            inet_pton(AF_INET, inet_ntoa(inner_ip_dest/*inner_arp_dest_ip*/), &(ep_ip.sin_addr));
            epkey.ip = ep_ip.sin_addr.s_addr;
            auto ep_value = db_client::get_instance().GetNeighborInMemory(&epkey);
//            endpoint_t ep_value;
//            ep_value = db_client::get_instance().GetNeighbor(trn_get_vni(vxlan->vni), inet_ntoa(inner_ip_dest));
            if (ep_value != nullptr) {
//                epkey.vni = trn_get_vni(vxlan->vni);
//                struct sockaddr_in ep_ip;
//                inet_pton(AF_INET, inet_ntoa(inner_ip_dest/*inner_arp_dest_ip*/), &(ep_ip.sin_addr));
//                epkey.ip = ep_ip.sin_addr.s_addr;
                // we now have key and value, can modify the packet and update the map now.
//                int ebpf_rc = bpf_map_update_elem((*fd), &epkey, &ep_value, BPF_ANY);
//                printf("AF_XDP: Inserted this neighbor into map: vip: %s, vni: %d, ebpf_rc: %d\n",
//                       inet_ntoa(inner_ip_dest), trn_get_vni(vxlan->vni), 0);

                /* Modify inner EitherHdr, pretend it's from target */
                trn_set_dst_mac(inner_eth, ep_value->mac);

                /* Keep overlay header, update outer header destinations */
                trn_set_src_dst_ip_csum(ip, ip->daddr, ep_value->hip, (eth + len));
                trn_set_src_mac(eth, eth->h_dest);
                trn_set_dst_mac(eth, ep_value->hmac);

                /*
             * Packet modification finished, read packet content again, in order to verify the mod
             * */

                struct ethhdr *eth = (struct ethhdr *) pkt;

                if (ntohs(eth->h_proto) != ETH_P_IP) {
//                    printf("%s\n", "AFTER MOD: returning false for this packet as it is NOT IP");
                    return false;
                }
//                printf("AFTER MOD: Packet length: %ld\n", len);
//                printf("AFTER MOD: Outer eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n"
//                       "eth size: %d\n",
//                       eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5],
//                       eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5],
//                       bpf_ntohs(eth->h_proto),
//                       sizeof(*eth));
//
//                // parse outer IP header
//                struct iphdr *ip = (struct iphdr *) (eth + 1/*sizeof(*eth)*/);
//                struct in_addr outer_ip_src;
//                outer_ip_src.s_addr = ip->saddr;
//                struct in_addr outer_ip_dest;
//                outer_ip_dest.s_addr = ip->daddr;
//                printf("AFTER MOD: Outer ip src: %s, ip dest: %s\n"
//                       "AFTER MOD: Outer ip ihl: %d, version: %d\n",
//                       inet_ntoa(outer_ip_src),inet_ntoa(outer_ip_dest),
//                       ip->ihl, ip->version);
//
//                // parse UDP header
//                struct udphdr *udp = (struct udphdr *) (ip + 1/*sizeof(*ip)*/);
//                printf("AFTER MOD: UDP dest: %d, UDP src: %d, == VXL_DSTPORT? %s\n",
//                       udp->dest, udp->source, (udp->dest==VXL_DSTPORT? "true" : "false"));
//
//                // parse VXLAN header
//                struct vxlanhdr_internal* vxlan = (struct vxlanhdr_internal *)(udp + 1/*sizeof(*udp)*/);
//                printf("AFTER MOD: VNI: %ld, \n",trn_get_vni(vxlan->vni));
//
//                // parse inner eth header
//                struct ethhdr *inner_eth = (struct ethhdr *)(vxlan + 1/*sizeof(*vxlan)*/);
//                printf("AFTER MOD: inner eth src: %x:%x:%x:%x:%x:%x, dest: %x:%x:%x:%x:%x:%x; next proto: 0x%x\n",
//                       inner_eth->h_source[0],inner_eth->h_source[1],inner_eth->h_source[2],inner_eth->h_source[3],inner_eth->h_source[4],inner_eth->h_source[5],
//                       inner_eth->h_dest[0],inner_eth->h_dest[1],inner_eth->h_dest[2],inner_eth->h_dest[3],inner_eth->h_dest[4],inner_eth->h_dest[5],
//                       inner_eth->h_proto);
//
//                // parse inner IP header
//                struct iphdr *inner_ip = (struct iphdr *)(inner_eth + 1 /*sizeof(*inner_eth)*/);
//                struct in_addr inner_ip_src, inner_ip_dest;
//                inner_ip_src.s_addr = inner_ip->saddr;
//                inner_ip_dest.s_addr = inner_ip->daddr;
//                printf("AFTER MOD: Inner IP src: %s\n", inet_ntoa(inner_ip_src));
//                printf("AFTER MOD: Inner IP dest: %s\n", inet_ntoa(inner_ip_dest));
                /* Here we sent the packet out of the receive port. Note that
		 * we allocate one entry and schedule it. Your design would be
		 * faster if you do batch processing/transmission */

                ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
                if (ret != 1) {
                    /* No more transmit slots, drop the packet */
                    return false;
                }

                xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
                xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
                xsk_ring_prod__submit(&xsk->tx, 1);
                xsk->outstanding_tx++;

                xsk->stats.tx_bytes += len;
                xsk->stats.tx_packets++;
//                printf("Packet sent via tx queue\n");
//                printf("<<<<<<<<<<  Finished processing packet  <<<<<<<<<<\n");

                return true;
            } else {
                printf("Can't find endpoint!\n");
                return false;
            }
        }

//        printf("Endpoing hip == 0, returning false.\n");
        return false;
    }

    return false;
}


static void handle_receive_packets(struct xsk_socket_info *xsk, int* fd)
{
    unsigned int rcvd, stock_frames, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;

    rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd)
        return;

    /* Stuff the ring with as much frames as possible */
    stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
                                    xsk_umem_free_frames(xsk));

    if (stock_frames > 0) {

        ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
                                     &idx_fq);

        /* This should not happen, but just in case */
        while (ret != stock_frames)
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
                                         &idx_fq);

        for (i = 0; i < stock_frames; i++)
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
                    xsk_alloc_umem_frame(xsk);

        xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
    }

    /* Process received packets */
//    printf("Received %d packets\n", rcvd);
    for (i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

        if (!process_packet(xsk, addr, len, fd))
            xsk_free_umem_frame(xsk, addr);

        xsk->stats.rx_bytes += len;
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk->stats.rx_packets += rcvd;

    /* Do we need to wake up the kernel for transmission */
    complete_tx(xsk);
//    printf("tx completed\n");
}

static void rx_and_process(struct config *cfg,
                           struct xsk_socket_info *xsk_socket, int* fd)
{
    struct pollfd fds[2];
    int ret, nfds = 1;

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
    fds[0].events = POLLIN;
    printf("%s\n", "Entering while loop to process packets.");
    while(!global_exit) {
        if (cfg->xsk_poll_mode) {
            ret = poll(fds, nfds, -1);
            if (ret <= 0 || ret > 1)
                continue;
        }
        handle_receive_packets(xsk_socket, fd);
    }
}

static void exit_application(int signal)
{
    signal = signal;
    global_exit = true;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = static_cast<xsk_umem_info *>(calloc(1, sizeof(*umem)));
    if (!umem)
        return nullptr;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                           nullptr);
    if (ret) {
        errno = -ret;
        return nullptr;
    }

    umem->buffer = buffer;
    return umem;
}

static struct bpf_object *open_bpf_object(const char *file, int ifindex)
{
    int err;
    struct bpf_object *obj;
    struct bpf_map *map;
    struct bpf_program *prog, *first_prog = NULL;

    struct bpf_object_open_attr open_attr = {
        .file = file,
        .prog_type = BPF_PROG_TYPE_XDP,
    };

    obj = bpf_object__open_xattr(&open_attr);

    bpf_object__for_each_program(prog, obj) {
        bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
        bpf_program__set_ifindex(prog, ifindex);
        if (!first_prog)
            first_prog = prog;
    }

    bpf_object__for_each_map(map, obj) {
        if (!bpf_map__is_offload_neutral(map))
            bpf_map__set_ifindex(map, ifindex);
    }

    if (!first_prog) {
        fprintf(stderr, "ERR: file %s contains no programs\n", file);
        return NULL;
    }

    return obj;
}

static int reuse_maps(struct bpf_object *obj, const char *path)
{
    struct bpf_map *map;

    if (!obj)
        return -ENOENT;

    if (!path)
        return -EINVAL;

    bpf_object__for_each_map(map, obj) {
        if (bpf_map__name(map) == "xsks_map"){
            printf("Try to reuse map: %s\n", bpf_map__name(map));
            int len, err;
            int pinned_map_fd;
            char buf[PATH_MAX];

            len = snprintf(buf, PATH_MAX, "%s/%s", path, bpf_map__name(map));
            if (len < 0) {
                return -EINVAL;
            } else if (len >= PATH_MAX) {
                return -ENAMETOOLONG;
            }

            pinned_map_fd = bpf_obj_get(buf);
            if (pinned_map_fd < 0) {
                printf("failed at bpf_obj_get for map: %s, buf: %s\n", bpf_map__name(map), buf);
                return pinned_map_fd;
            }

            err = bpf_map__reuse_fd(map, pinned_map_fd);
            if (err) {
                printf("failed at bpf_map__reuse_fd for map: %s\n", bpf_map__name(map));
                return err;
            }
        }else {
            printf("Skipping map: %s\n", bpf_map__name(map));
        }
    }

    return 0;
}

struct bpf_object *load_bpf_object_file_reuse_maps(const char *file,
                                                   int ifindex,
                                                   const char *pin_dir)
{
    int err;
    struct bpf_object *obj;

    obj = open_bpf_object(file, ifindex);
    if (!obj) {
        fprintf(stderr, "ERR: failed to open object %s\n", file);
        return NULL;
    }

    err = reuse_maps(obj, pin_dir);
    if (err) {
        fprintf(stderr, "ERR: failed to reuse maps for object %s, pin_dir=%s, err=%d\n",
                file, pin_dir, err);
        return NULL;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
                file, err, strerror(-err));
        return NULL;
    }

    return obj;
}

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex)
{
    int first_prog_fd = -1;
    struct bpf_object *obj;
    int err;

    /* This struct allow us to set ifindex, this features is used for
	 * hardware offloading XDP programs (note this sets libbpf
	 * bpf_program->prog_ifindex and foreach bpf_map->map_ifindex).
	 */
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex   = ifindex,
    };
    prog_load_attr.file = filename;

    /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
                filename, err, strerror(-err));
        return NULL;
    }

    /* Notice how a pointer to a libbpf bpf_object is returned */
    return obj;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
    int err;

    /* libbpf provide the XDP net_device link-level hook attach helper */
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
        /* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

        __u32 old_flags = xdp_flags;

        xdp_flags &= ~XDP_FLAGS_MODES;
        xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
        err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
        if (!err)
            err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
    }
    if (err < 0) {
        fprintf(stderr, "ERR: "
                        "ifindex(%d) link set xdp fd failed (%d): %s\n",
                ifindex, -err, strerror(-err));

        switch (-err) {
        case EBUSY:
        case EEXIST:
            fprintf(stderr, "Hint: XDP already loaded on device"
                            " use --force to swap/replace\n");
            break;
        case EOPNOTSUPP:
            fprintf(stderr, "Hint: Native-XDP not supported"
                            " use --skb-mode or --auto-mode\n");
            break;
        default:
            break;
        }
        return EXIT_FAIL_XDP;
    }

    return EXIT_OK;
}

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg)
{
    struct bpf_program *bpf_prog;
    struct bpf_object *bpf_obj;
    int offload_ifindex = 0;
    int prog_fd = -1;
    int err;

    /* If flags indicate hardware offload, supply ifindex */
    if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
        offload_ifindex = cfg->ifindex;

    /* Load the BPF-ELF object file and get back libbpf bpf_object */
    if (cfg->reuse_maps)
        bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename,
                                                  offload_ifindex,
                                                  cfg->pin_dir);
    else
        bpf_obj = load_bpf_object_file(cfg->filename, offload_ifindex);
    if (!bpf_obj) {
        fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
        exit(EXIT_FAIL_BPF);
    }
    /* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

    if (cfg->progsec[0])
        /* Find a matching BPF prog section name */
        bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
    else
        /* Find the first program */
        bpf_prog = bpf_program__next(NULL, bpf_obj);

    if (!bpf_prog) {
        fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
        exit(EXIT_FAIL_BPF);
    }

    strncpy(cfg->progsec, bpf_program__title(bpf_prog, false), sizeof(cfg->progsec));

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd failed\n");
        exit(EXIT_FAIL_BPF);
    }

    /* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
    err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
    if (err)
        exit(err);

    return bpf_obj;
}

void af_xdp_user::run_af_xdp()
{
    printf("%s", "af_xdp started\n");
    std::string table_name_neighbor_ebpf_map = "/sys/fs/bpf/endpoints_map";
    int fd_neighbor_ebpf_map = bpf_obj_get(table_name_neighbor_ebpf_map.c_str());
//    if (fd_neighbor_ebpf_map < 0) {
//        printf("Failed to get xdp neighbor endpoint map fd, exiting\n");
//        return;
//    } else {
//        printf("Got xdp neighbor endpoint map fd %d\n", fd_neighbor_ebpf_map);
//    }

    int ret;
    int xsks_map_fd;
    void *packet_buffer;
    uint64_t packet_buffer_size;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct config cfg;

    cfg.ifindex = -1;
    cfg.do_unload = false;
    // TODO: fill in the file name and progsec in CPP style
    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk_socket;
    struct bpf_object *bpf_obj = nullptr;

    /* Global shutdown handler*/
    signal(SIGINT, exit_application);

    /* Command line options can change progsec*/
//    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
    // TODO: Get rid of getting the config from argc/argv, hardcode it for the time being.
    // interface name
    cfg.ifname = "enp4s0f1";
    cfg.ifindex = if_nametoindex(cfg.ifname);
    // skb mode
    cfg.xdp_flags &= ~XDP_FLAGS_MODES;
    cfg.xdp_flags |= XDP_FLAGS_DRV_MODE;
    cfg.xsk_bind_flags &= XDP_COPY;//XDP_ZEROCOPY;
    cfg.xsk_bind_flags |= XDP_ZEROCOPY;//XDP_COPY;

    // queue_id, default = 0
    cfg.xsk_if_queue = 0;
    // NOT using poll
    cfg.xsk_poll_mode = true;
    // not doing unload this time
    cfg.do_unload = false;
    // progsec of the xdp program
    std::string progsec_string = "transit";
    strncpy(cfg.progsec, progsec_string.c_str(), sizeof(cfg.progsec));
//    progsec_string.copy(cfg.progsec, progsec_string.size());

    // absolute path for the xdp.o file
    std::string file_name = "/trn_xdp/trn_transit_xdp_ebpf.o";
//    strncpy(cfg.filename, file_name.c_str(), sizeof(cfg.filename));
//    file_name.copy(cfg.filename, file_name.size());
    // reuse maps, try NOT to create a new map.
    cfg.reuse_maps = true;
    std::string pin_dir = "/sys/fs/bpf";
    strncpy(cfg.pin_dir, pin_dir.c_str(), sizeof(cfg.pin_dir));
//    pin_dir.copy(cfg.pin_dir, pin_dir.size());

    /* Required option */
    if (cfg.ifindex == -1) {
        printf("%s", "ERROR: Required option --dev missing\n\n");
//        usage(argv[0], __doc__, long_options, (argc == 1));
        exit(EXIT_FAIL_OPTION);
    }

    /* Unload XDP program if requested */
    if (cfg.do_unload) {
//        int rc = xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
        exit(-1);
    }

    /* Load custom program if configured */
    if (cfg.filename[0] != 0) {
        struct bpf_map *map;

        bpf_obj = load_bpf_and_xdp_attach(&cfg);
        if (!bpf_obj) {
            /* Error handling done in load_bpf_and_xdp_attach() */
            exit(EXIT_FAILURE);
        }

        /* We also need to load the xsks_map */
        map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
        xsks_map_fd = bpf_map__fd(map);
        if (xsks_map_fd < 0) {
            fprintf(stderr, "ERROR: no xsks map found: %s\n",
                    strerror(xsks_map_fd));
            exit(EXIT_FAILURE);
        }
    } else {
        printf("%s\n", "Empty config filename, not loading/attaching");
    }

    /* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        printf("%s", "ERROR: setrlimit(RLIMIT_MEMLOCK) \n");
        exit(EXIT_FAILURE);
    }

    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&packet_buffer,
                       getpagesize(), /* PAGE_SIZE aligned */
                       packet_buffer_size)) {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Initialize shared packet_buffer for umem usage */
    umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (umem == NULL) {
        fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Open and configure the AF_XDP (xsk) socket */
    xsk_socket = xsk_configure_socket(&cfg, umem);
    if (xsk_socket == NULL) {
        fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    /* Receive and count packets than drop them */
    rx_and_process(&cfg, xsk_socket, &fd_neighbor_ebpf_map);

    /* Cleanup */
    xsk_socket__delete(xsk_socket->xsk);
    xsk_umem__delete(umem->umem);
//    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

    return /*EXIT_OK*/;
}
