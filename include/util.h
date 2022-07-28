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
    throw std::invalid_argument("Virtual ipv4 address is not in the expected format");
  }
  return sa.sin_addr.s_addr;
}

static inline std::uint8_t getNum(char hexChar) {
    if (hexChar >= '0' && hexChar <= '9') {
        return hexChar - '0';
    }
    return (hexChar - 'A' + 10);
}

#endif
