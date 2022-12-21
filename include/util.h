// MIT License
// Copyright(c) 2022 Futurewei Cloud
//
//     Permission is hereby granted,
//     free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction,
//     including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and / or sell copies of the Software, and to permit persons
//     to whom the Software is furnished to do so, subject to the following conditions:
//
//     The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
//     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <arpa/inet.h>
#include <cstring>
using namespace std;

// the number of characters needed to store the HEX form of IP address
#define HEX_IP_BUFFER_SIZE 12

// vxlan-generic openflow outport number
#define VXLAN_GENERIC_OUTPORT_NUMBER "100"

// maximum valid value of a VNI, that (2^24) - 1
// applicable for VxLAN, GRE, VxLAN-GPE and Geneve
#define MAX_VALID_VNI 16777215

#define MAX_VALID_VLAN_ID 4094

#define cast_to_nanoseconds(x) chrono::duration_cast<chrono::nanoseconds>(x)
#define cast_to_microseconds(x) chrono::duration_cast<chrono::microseconds>(x)
#define us_to_ms(x) x / 1000 // convert from microseconds to millseconds

static inline long ip4tol(const string ip) {
  struct sockaddr_in sa;
  if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 1) {
//    throw std::invalid_argument("Virtual ipv4 address is not in the expected format");
  }
  return sa.sin_addr.s_addr;
}

static inline std::uint8_t getNum(char hexChar) {
    if (hexChar >= '0' && hexChar <= '9') {
        return hexChar - '0';
    }
    return (hexChar - 'A' + 10);
}


static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
    uint16_t res = (uint16_t)csum;

    res += (__u16)addend;
    return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
    return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 present)
{
    *sum = ~csum16_add(csum16_sub(~(*sum), old), present);
}

static inline void trn_set_mac(void *dst, unsigned char *mac)
{
    unsigned short *d = static_cast<unsigned short *>(dst);
    unsigned short *s = (unsigned short *)mac;

    d[0] = s[0];
    d[1] = s[1];
    d[2] = s[2];
}

static inline void trn_set_dst_mac(void *data, unsigned char *dst_mac)
{
    trn_set_mac(data, dst_mac);
}

static inline void trn_set_src_mac(void *data, unsigned char *src_mac)
{
    uint8_t *tmp = static_cast<uint8_t *>(data);
    trn_set_mac((void*)(tmp + 6), src_mac);
}

static __be32 trn_get_vni(const __u8 *vni)
{
    /* Big endian! */
    return (vni[0] << 16) | (vni[1] << 8) | vni[2];
}

static inline void trn_set_src_ip(void *data, void *data_end, __u32 saddr)
{
    int off = offsetof(struct iphdr, saddr);
    uint8_t *tmp = static_cast<uint8_t *>(data);

    __u32 *addr = (__u32*)(tmp + off);
    if ((void *)addr > data_end)
        return;

    *addr = saddr;
}

static inline void trn_set_dst_ip(void *data, void *data_end, __u32 daddr)
{
    int off = offsetof(struct iphdr, daddr);
    uint8_t *tmp = static_cast<uint8_t *>(data);

    __u32 *addr = (__u32 *)(tmp + off);
    if ((void *)addr > data_end)
        return;

    *addr = daddr;
}

static inline __u16 trn_csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static inline void trn_ipv4_csum_inline(void *iph, __u64 *csum)
{
    __u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
    for (int i = 0; i<sizeof(struct iphdr)>> 1; i++) {
        *csum += *next_iph_u16++;
    }
    *csum = trn_csum_fold_helper(*csum);
}

static inline void trn_set_src_dst_ip_csum(struct iphdr *ip,
                                           __u32 saddr, __u32 daddr, void *data_end)
{
    /* Since the packet destination is being rewritten we also
	decrement the TTL */
    ip->ttl--;

    __u64 csum = 0;
    trn_set_src_ip(ip, data_end, saddr);
    trn_set_dst_ip(ip, data_end, daddr);
    csum = 0;
    ip->check = 0;
    trn_ipv4_csum_inline(ip, &csum);
    ip->check = csum;

    //    printf("Modified IP Address, src: 0x%x, dst: 0x%x, csum: 0x%x\n",
    //              ip->saddr, ip->daddr, ip->check);
}

static inline void trn_swap_src_dst_mac(void *data)
{
    unsigned short *p = static_cast<unsigned short *>(data);
    unsigned short tmp[3];

    tmp[0] = p[0];
    tmp[1] = p[1];
    tmp[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = tmp[0];
    p[4] = tmp[1];
    p[5] = tmp[2];
}
#endif
