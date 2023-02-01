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

#include <iostream>
#include <memory>
#include <mutex>
#include <sqlite_orm.h>
#include <concurrency/ConcurrentHashMap.h>
#include "dispatch_queue.h"
#include "xdp/trn_datamodel.h"
#include "util.h"

using namespace sqlite_orm;


struct Neighbor {
    int vni;
    std::string vpc_ip;
    std::string host_ip;
    std::string vpc_mac;
    std::string host_mac;
    int version;
}; // local db table 1 - neighbor info table that stores the latest neighbors (if there are version updates per neighbor) received from ArionMaster

struct NeighborProgrammingState {
    int version;
}; // local db table 2 - neighbor ebpf programmed version

struct SecurityGroupPortBinding {
    std::string port_id; // vni-vpc_ip
    std::string security_group_id;
    int version;
}; // local db table 3, stores the mapping between port and security group, 1 group can have multiple rules.

struct SecurityGroupRule {
    std::string id; //UUID, should be key in DB
    std::string security_group_id;
    std::string remote_group_id;
    std::string direction;
    std::string remote_ip_prefix;
    std::string protocol;
    int port_range_max;
    int port_range_min;
    std::string ether_type;
    int vni;
    int version;
};  // local db table 3, security group rule table that stores the latest security group rules (if there are version updates per neighbor) received from ArionMaster

struct SecurityGroupPortBindingProgrammingState {
    int version;
}; // local db table 2 - security rule ebpf programmed version

// copied from arp_hash in ACA
struct EndpointHash {
    size_t operator()(const endpoint_key_t &e) const{
        return std::hash<__u32>()(e.vni) ^ (std::hash<__u32>()(e.ip) << 1);
    }
};

struct EndpointEqual {
    bool operator() (const endpoint_key_t &e, const endpoint_key_t &f) const {
        return (e.vni == f.vni) && (e.ip == f.ip);
    }
};

struct SecurityGroupRuleHash {
    size_t operator()(const sg_cidr_key_t &e) const{
        return std::hash<__u32>()(e.prefixlen) ^ std::hash<__u32>()(e.vni) ^ std::hash<__u16>()(e.port) ^
               std::hash<__u8>()(e.direction) ^ std::hash<__u8>()(e.protocol) ^ std::hash<__u32>()(e.local_ip) ^
               std::hash<__u32>()(e.remote_ip);
    }
};

struct SecurityGroupRuleEqual {
    bool operator() (const sg_cidr_key_t &e, const sg_cidr_key_t &f) const {
        return (e.remote_ip == f.remote_ip) && (e.local_ip == f.local_ip) && (e.protocol == f.protocol) &&
               (e.direction == f.direction) && (e.port == f.port) && (e.vni == f.vni) && (e.prefixlen == f.prefixlen);
    }
};

static std::string g_local_db_path = "/var/local/arion/arion_wing.db";

inline auto make_storage_query () {
    auto storage = make_storage(g_local_db_path,
                                make_table("neighbor",
                                           make_column("vni", &Neighbor::vni),
                                           make_column("vpc_ip", &Neighbor::vpc_ip),
                                           make_column("host_ip", &Neighbor::host_ip),
                                           make_column("vpc_mac", &Neighbor::vpc_mac),
                                           make_column("host_mac", &Neighbor::host_mac),
                                           make_column("version", &Neighbor::version),
                                           primary_key(&Neighbor::vni, &Neighbor::vpc_ip)
                                                   ),
                                make_table("journal_neighbor",
                                           make_column("version", &NeighborProgrammingState::version),
                                           primary_key(&NeighborProgrammingState::version)
                                                   ),
                                make_table("security_group_rule",
                                           make_column("id", &SecurityGroupRule::id),
                                           make_column("security_group_id", &SecurityGroupRule::security_group_id),
                                           make_column("remote_group_id", &SecurityGroupRule::remote_group_id),
                                           make_column("direction", &SecurityGroupRule::direction),
                                           make_column("remote_ip_prefix", &SecurityGroupRule::remote_ip_prefix),
                                           make_column("protocol", &SecurityGroupRule::protocol),
                                           make_column("port_range_max", &SecurityGroupRule::port_range_max),
                                           make_column("port_range_min", &SecurityGroupRule::port_range_min),
                                           make_column("ether_type", &SecurityGroupRule::ether_type),
                                           make_column("vni", &SecurityGroupRule::vni),
                                           make_column("version", &SecurityGroupRule::version),
                                           primary_key(&SecurityGroupRule::id)
                                                   ),
                                make_table("security_group_port_binding",
                                           make_column("port_id", &SecurityGroupPortBinding::port_id),
                                           make_column("security_group_id", &SecurityGroupPortBinding::security_group_id),
                                           make_column("version", &SecurityGroupPortBinding::version),
                                           primary_key(&SecurityGroupPortBinding::port_id, &SecurityGroupPortBinding::security_group_id, &SecurityGroupPortBinding::version)
                                                   ),
                                // 1 version is written when all related SecurityGroupRules of a SecurityGroupPortBinding
                                // is programmed into the eBPF map and written into the DB.
                                make_table("journal_security_group_rules",
                                           make_column("version", &SecurityGroupPortBindingProgrammingState::version),
                                           primary_key(&SecurityGroupPortBindingProgrammingState::version)
                                                   )
    );
    storage.sync_schema();
    return storage;
};

using Storage = decltype(make_storage_query());

class db_client {
public:
    static db_client &get_instance() {
        static db_client instance;
        return instance;
    };

    Storage local_db = make_storage_query();

    using NeighborPrepareStatement = decltype(local_db.prepare(select(columns(&Neighbor::host_ip, &Neighbor::vpc_mac, &Neighbor::host_mac),
                                                 where(is_equal((&Neighbor::vni), 0) and is_equal((&Neighbor::vpc_ip), "127.0.0.1")))));
    NeighborPrepareStatement query_neighbor_statement = local_db.prepare(
            select(
                    columns(&Neighbor::host_ip, &Neighbor::vpc_mac, &Neighbor::host_mac),
                    where(
                            is_equal((&Neighbor::vni), 0)
                            and
                            is_equal((&Neighbor::vpc_ip), "127.0.0.1")
                            )
                    )
            );
    // Create local db writer single thread execution queue
    dispatch_queue local_db_writer_queue = dispatch_queue("Local db background write queue", 1);

    std::unordered_map<endpoint_key_t, endpoint_t, EndpointHash, EndpointEqual> endpoint_cache;

    std::unordered_map<sg_cidr_key_t, sg_cidr_t, SecurityGroupRuleHash, SecurityGroupRuleEqual> sg_rule_cache;


    // function that will be called at the beginning of the program, reads rows from the neighbor table
    // and fills the in-memory endpoint cache, which is used for fast lookup.
    void FillEndpointCacheFromDB() {
        std::string table_name_sg_ebpf_map = "/sys/fs/bpf/security_group_map";
        int fd_security_group_ebpf_map = bpf_obj_get(table_name_sg_ebpf_map.c_str());
        printf("DB Client: sg map fd: %ld\n", fd_security_group_ebpf_map);

        std::string table_name_sg_cidr_map = "/sys/fs/bpf/sg_cidr_map";
        int fd_sg_cidr_ebpf_map = bpf_obj_get(table_name_sg_cidr_map.c_str());
        printf("DB Client: sg cidr map fd: %ld\n", fd_security_group_ebpf_map);

        // Get all neighbors from SQLite Database
        auto get_all_neighbors_statement = local_db.prepare(
                select(
                        columns(&Neighbor::vni, &Neighbor::vpc_ip, &Neighbor::host_mac, &Neighbor::vpc_mac, &Neighbor::host_ip)
                        )
                );
        auto rows = local_db.execute(get_all_neighbors_statement);
        printf("Retrieved %ld neighbors from local DB\n", rows.size());
        for (auto & row : rows) {
            int vni = get<0>(row);
            auto vpc_ip = get<1>(row).c_str();
            auto host_ip  = get<4>(row).c_str();
            auto vpc_mac = get<3>(row).c_str();
            auto host_mac = get<2>(row).c_str();
//            printf("Retrieved this endpoint from local DB: VNI: %ld, vpc_ip: %s, host_mac: %s, vpc_mac: %s, host_ip: %s\n",
////                   get<0>(row), get<1>(row).c_str(), get<2>(row).c_str(), get<3>(row).c_str(), get<4>(row).c_str()
//                   vni, vpc_ip, host_mac, vpc_mac, host_ip
//                   );
            endpoint_key_t key;
            key.vni = vni; //(get<0>(row));
            struct sockaddr_in endpoint_vpc_ip_socket;
            inet_pton(AF_INET, vpc_ip, &(endpoint_vpc_ip_socket.sin_addr));
            key.ip = endpoint_vpc_ip_socket.sin_addr.s_addr;
            endpoint_t value;
            std::sscanf(vpc_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                        &value.mac[0], &value.mac[1], &value.mac[2],
                        &value.mac[3], &value.mac[4], &value.mac[5]);

            std::sscanf(host_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                        &value.hmac[0], &value.hmac[1], &value.hmac[2],
                        &value.hmac[3], &value.hmac[4], &value.hmac[5]);
            struct sockaddr_in endpoint_host_ip_socket;
            inet_pton(AF_INET, host_ip, &(endpoint_host_ip_socket.sin_addr));
            value.hip = endpoint_host_ip_socket.sin_addr.s_addr;
            endpoint_cache[key] = value;
//            endpoint_cache.insert(key, value);
//            printf("Inserted this endpoint into cache: VNI: %ld, vpc_ip: %s, ", key.vni, inet_ntoa(endpoint_vpc_ip_socket.sin_addr));
//            printf("host_mac: %x:%x:%x:%x:%x:%x, vpc_mac: %x:%x:%x:%x:%x:%x, host_ip: %s\n",
//                   value.hmac[0],value.hmac[1],value.hmac[2],value.hmac[3],value.hmac[4],value.hmac[5],
//                   value.mac[0],value.mac[1],value.mac[2],value.mac[3],value.mac[4],value.mac[5],
//                   inet_ntoa(endpoint_host_ip_socket.sin_addr)
//            );
//            printf("Finished one endpoint\n");
            /*
            security_group_key_t sg_key;
            sg_key.vni = vni;
            sg_key.ip = endpoint_vpc_ip_socket.sin_addr.s_addr;
            sg_key.direction = 0;
            security_group_t sg_value;
            sg_value.sg_id = 12345;
            sg_value.action = 1;
//            int sg_map_insert_rc = bpf_map_update_elem(fd_security_group_ebpf_map, &sg_key, &sg_value, BPF_ANY);
//            printf("Sg map insert rc: %ld\n", sg_map_insert_rc);
            sg_cidr_key_t sg_cidr_key;
            // add the number of bits for all fields, except prefexlen and dst_ip, then add the cidr range, in this case it is /24
            sg_cidr_key.prefixlen = (32 + 16 + 8 + 8 + 32 + 24);
//            inet_pton(AF_INET, vpc_ip, sg_cidr_key.lpm_key.data);
            sg_cidr_key.local_ip = endpoint_vpc_ip_socket.sin_addr.s_addr;
            sg_cidr_key.remote_ip = endpoint_vpc_ip_socket.sin_addr.s_addr;
            sg_cidr_key.vni = vni;
            sg_cidr_key.direction = 1;
            sg_cidr_key.protocol = IPPROTO_TCP;
            sg_cidr_key.port = 888;
            int sg_map_insert_rc = bpf_map_update_elem(fd_sg_cidr_ebpf_map, &sg_cidr_key, &sg_value, BPF_ANY);
            if (sg_map_insert_rc != 0) {
                printf("Error for inserting into lpm map: %s", std::strerror(errno));
            }
            */
//            printf("Sg map insert rc: %ld\n", sg_map_insert_rc);


        }
        printf("Finished retrieving from local DB, not endpoint cache has %ld endpoints\n", endpoint_cache.size());
    }
    int FindLKGVersion() {
        int lkg_ver = 0;

        /* original sql is
        SELECT  MIN(mo.version) + 1
        FROM    journal AS mo
        WHERE   NOT EXISTS
                (
                SELECT  0 - mi.version
                FROM    journal AS mi
                WHERE   mo.version + 1 = mi.version
                );
    */

        using als_mo = alias_a<NeighborProgrammingState>;
        using als_mi = alias_b<NeighborProgrammingState>;
        auto ver_gaps = local_db.select(alias_column<als_mo>(&NeighborProgrammingState::version),
                                        from<als_mo>(),
                                        where(not exists(
                                                select(0 - c(alias_column<als_mi>(&NeighborProgrammingState::version)),
                                                       from<als_mi>(),
                                                       where(is_equal(c(alias_column<als_mo>(&NeighborProgrammingState::version)) + 1, alias_column<als_mi>(&NeighborProgrammingState::version)))
                                                               ))));

        // lkg version:
        //   case 1 - if no ver gap, the query above will return the max version (since this version is already programmed, so return max + 1)
        //   case 2 - if there's ver gap, then always locate the min ver gap (as above, return minVerGap + 1)
        //   case 3 - if the table is empty like new launched instance, then always sync/watch from server with version 1
        //            (since server syncs including the version agent provides, so sync/watch from version 1 means sync everything
        if (ver_gaps.size() > 0) {
            lkg_ver = *std::min_element(ver_gaps.begin(), ver_gaps.end());
        }

        return lkg_ver + 1;
    };

    endpoint_t GetNeighbor(int vni, std::string vpc_ip) {
        endpoint_t found_neighbor;
        found_neighbor.hip = 0;
//        printf("GetNeighbor with VNI: [%d], vpc_ip: [%s]\n", vni, vpc_ip.c_str());
        get<0>(query_neighbor_statement) = vni;
        get<1>(query_neighbor_statement) = vpc_ip.c_str();
//        printf("Statement: %s\n", query_neighbor_statement.sql().c_str());
        auto rows = local_db.execute(query_neighbor_statement);
//        printf("Found %ld rows\n", rows.size());
        for (auto& row : rows) {
            struct sockaddr_in ep_hip;
            inet_pton(AF_INET, get<0>(row).c_str(), &(ep_hip.sin_addr));
            found_neighbor.hip = ep_hip.sin_addr.s_addr;

            std::sscanf(get<1>(row).c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                        &found_neighbor.mac[0], &found_neighbor.mac[1], &found_neighbor.mac[2],
                        &found_neighbor.mac[3], &found_neighbor.mac[4], &found_neighbor.mac[5]);

            std::sscanf(get<2>(row).c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                        &found_neighbor.hmac[0], &found_neighbor.hmac[1], &found_neighbor.hmac[2],
                        &found_neighbor.hmac[3], &found_neighbor.hmac[4], &found_neighbor.hmac[5]);

//            printf("host_ip: %s, vpc_mac: %s, host_mac: %s\n", get<0>(row).c_str(), get<1>(row).c_str(), get<2>(row).c_str());
        }
        return found_neighbor;
    }

    endpoint_t GetNeighborInMemory(endpoint_key_t  key) {
        auto iterator = endpoint_cache.find(key);
        if (iterator == endpoint_cache.end()) {
          return {
                .hip = 0,
            };
        }
        auto endpoint_value = iterator->second;//endpoint_cache[*key];
        return endpoint_value;
    }
};