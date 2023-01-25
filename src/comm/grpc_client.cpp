/*
 *
 * Copyright 2015 gRPC authors.
 * Copyright 2022 The Arion Authors - file modified.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <atomic>
#include <memory>
#include <algorithm>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "marl/defer.h"
#include "marl/event.h"
#include "marl/scheduler.h"
#include "marl/waitgroup.h"

#include "arionmaster.grpc.pb.h"
#include "db_client.h"
#include "grpc_client.h"
//#include "xdp/trn_datamodel.h"

using namespace arion::schema;

void ArionMasterWatcherImpl::RequestArionMaster(vector<ArionWingRequest *> *request_vector,
                                                  grpc::CompletionQueue *cq) {
    grpc::ClientContext ctx;
    arion::schema::NeighborRule reply;

    // prepared statements for better performance of db writing in completion queue

    // neighbor state, has ebpf map and local db table
    auto add_or_update_neighbor_db_stmt = db_client::get_instance().local_db.prepare(replace(Neighbor{ 0, "", "", "", "", 0 }));
    auto add_programmed_neighbor_version_db_stmt = db_client::get_instance().local_db.prepare(insert(NeibghborProgrammingState{ 0 }));

    // security group rules, has local db, but NOT ebpf map
    auto add_or_update_security_group_rule_db_stmt = db_client::get_instance().local_db.prepare(replace(::SecurityGroupRule{ "", "", "", "", "", 0, 0, "", 0, 0 }));

    // security group port binding, has local db, needs to query security group rules to insert into eBPF map.
    auto add_or_update_security_group_port_binding_stmt = db_client::get_instance().local_db.prepare(replace(::SecurityGroupPortBinding{"", ""}));
    auto add_programmed_security_group_port_binding_version_db_stmt = db_client::get_instance().local_db.prepare(insert(SecurityGroupPortBindingProgrammingState{ 0 }));

    // check current grpc channel state, try to connect if needed
    grpc_connectivity_state current_state = chan_->GetState(true);
    if (current_state == grpc_connectivity_state::GRPC_CHANNEL_SHUTDOWN ||
        current_state == grpc_connectivity_state::GRPC_CHANNEL_TRANSIENT_FAILURE) {
        printf("%s, it is: [%d]\n",
               "Channel state is not READY/CONNECTING/IDLE. Try to reconnnect.",
               current_state);
        this->ConnectToArionMaster();
    }

    void* got_tag;
    bool ok = false;
    AsyncClientCall *call = new AsyncClientCall;

    int tag_watch = 1;
    printf("Completion queue: initial task, async watch\n");
    stub_->AsyncWatch(&call->context, cq, (void*) tag_watch);
    call->stream = stub_->AsyncWatch(&call->context, cq, (void*)tag_watch);

    // start time
    std::chrono::_V2::steady_clock::time_point start;

    std::atomic<int> i(tag_watch + 1);
    bool write_done = false;
    while (cq->Next(&got_tag, &ok)) {
        printf("Read one from grpc stream\n");
        if (ok) {
            if (!write_done) {
                printf("Completion queue: initial task response received\n");

                printf("Completion queue: write async watch ArionWingRequest of [group, revision] to stream\n");
                for (auto &request : *request_vector) {
                    call->stream->Write(*request, (void*)tag_watch);
                    printf("Just wrote request with rev: [%ld], map: [%ld] and group id: [%ld]\n",
                           request->rev(), request->map().c_str(), request->group().c_str()
                           );
                }

                write_done = true;
            } else {
                call->stream->Read(&call->reply, got_tag);
                if (call->reply.has_neighbor_rule()) {
                    auto vni = call->reply.neighbor_rule().tunnel_id();
                    auto vpc_ip = call->reply.neighbor_rule().ip();
                    auto vpc_mac = call->reply.neighbor_rule().mac();
                    auto host_ip = call->reply.neighbor_rule().hostip();
                    auto host_mac = call->reply.neighbor_rule().hostmac();
                    auto ver = call->reply.neighbor_rule().version();
                    int fd = fd_neighbor_ebpf_map;

                    // non-empty rule
                    if ("" != vpc_ip) {
                        marl::schedule([this, &i, vni, vpc_ip, vpc_mac, host_ip, host_mac, ver, fd,
                                        &add_or_update_neighbor_db_stmt, &add_programmed_neighbor_version_db_stmt] {
                            // step #1 - check and store <neighbor_key, version> as <k, v> in concurrent hash map
                            std::string neighbor_key = std::to_string(vni) + "-" + vpc_ip;
                            printf("vpc_ip is NOT empty: [%s]\n", vpc_ip.c_str());
                            bool ebpf_ignored = false;
                            bool map_updated = false;
                            int update_ct = 0, max_update_ct = 5;

                            while (!map_updated && (update_ct < max_update_ct)) {
                                printf("Inside while loop, map_updated = [%b], update_ct = [%ld], max_update_ct = [%ld]\n",
                                       map_updated, update_ct, max_update_ct);
                                auto neighbor_pos = neighbor_task_map.find(neighbor_key);
                                if (neighbor_pos == neighbor_task_map.end()) {
                                    // key not found, try insert. The function returns successful only when key not exists when inserting
                                    auto res_insert =
                                            neighbor_task_map.insert(neighbor_key, ver);
                                    if (res_insert.second) {
                                        // means successfully inserted, done with update
                                        map_updated = true;
                                        printf("Found neighbor key in neighbor_task_map\n");
                                    } // 'else' means another thread already inserted before me, then it's not an insert case and next time in the loop will go to case of update
                                } else {
                                    printf("Didn't find neighbor key in neighbor_task_map\n");
                                    // key found, means multi neighbor versions might update at the same time
                                    int cur_ver = neighbor_pos->second;

                                    if (ver > cur_ver) {
                                        // only update neighbor version
                                        //   1. when received (from ArionMaster) neighbor version is greater than current version in map
                                        //   2. and only if the element to update is the original element (version in 'find')
                                        if (neighbor_task_map.assign_if_equal(neighbor_key, ver, cur_ver)) {
                                            map_updated = true;
                                        }
                                    } else {
                                        // otherwise
                                        // ignore:
                                        //   1. update concurrent hash map
                                        //   2. update ebpf map to not overwrite new data with out dated data
                                        //   3. update local db table 1 (table 1 is for local lookup) since it is an old version
                                        // update: journal table (since this skipped version is treated as programming succeeded)
                                        ebpf_ignored = true;
                                        map_updated = true;
                                    }
                                }

                                update_ct++;
                            }

                            if (map_updated) {
                                if (!ebpf_ignored) {
                                    printf("ebpf_ignored = false\n");
                                    // step #2 - sync syscall ebpf map programming with return code
                                    endpoint_key_t epkey;
                                    epkey.vni = vni;
                                    struct sockaddr_in ep_ip;
                                    inet_pton(AF_INET, vpc_ip.c_str(), &(ep_ip.sin_addr));
                                    epkey.ip = ep_ip.sin_addr.s_addr;
                                    printf("Filled in ep.ip\n");
                                    endpoint_t ep;
                                    struct sockaddr_in ep_hip;
                                    inet_pton(AF_INET, host_ip.c_str(), &(ep_hip.sin_addr));
                                    ep.hip = ep_hip.sin_addr.s_addr;
                                    printf("Filled in ep.hip\n");

                                    std::sscanf(vpc_mac.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                                                &ep.mac[0], &ep.mac[1], &ep.mac[2],
                                                &ep.mac[3], &ep.mac[4], &ep.mac[5]);
                                    printf("Filled in ep.mac\n");

                                    std::sscanf(host_mac.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                                                &ep.hmac[0], &ep.hmac[1], &ep.hmac[2],
                                                &ep.hmac[3], &ep.hmac[4], &ep.hmac[5]);
                                    printf("Filled in ep.hmac\n");

                                    //disabling the element udpate, so that all packets will be sent to user space program.

                                    int ebpf_rc = bpf_map_update_elem(fd, &epkey, &ep, BPF_ANY);
                                    // also put in local in memory cache
                                    db_client::get_instance().endpoint_cache[epkey] = ep;//.insert(epkey, ep);
                                    printf("GPPC: Inserted this neighbor into map: vip: %s, vni: %d\n", vpc_ip.c_str(), vni);
                                    // step #3 - async call to write/update to local db table 1
                                    db_client::get_instance().local_db_writer_queue.dispatch([vni, vpc_ip, host_ip, vpc_mac, host_mac, ver, &add_or_update_neighbor_db_stmt] {
                                        get<0>(add_or_update_neighbor_db_stmt) = { vni, vpc_ip, host_ip, vpc_mac, host_mac, ver };
                                        db_client::get_instance().local_db.execute(add_or_update_neighbor_db_stmt);
                                    });
                                    printf("Dispatched local db neighbor insert\n");
                                    // step #4 (case 1) - when ebpf programming not ignored, write to table 2 (programming journal) when programming succeeded
                                    if (0 == ebpf_rc) {
                                        db_client::get_instance().local_db_writer_queue.dispatch([ver, &add_programmed_neighbor_version_db_stmt] {
                                            get<0>(add_programmed_neighbor_version_db_stmt) = { ver };
                                            db_client::get_instance().local_db.execute(
                                                    add_programmed_neighbor_version_db_stmt);
                                        });
                                    }
                                    printf("Dispatched local db journal insert\n");
                                } else {
                                    printf("ebpf_ignored = true\n");
                                    // step #4 (case 2) - always write to local db table 2 (programming journal) when version intended ignored (no need to program older version)
                                    db_client::get_instance().local_db_writer_queue.dispatch([ver, &add_programmed_neighbor_version_db_stmt] {
                                        get<0>(add_programmed_neighbor_version_db_stmt) = { ver };
                                        db_client::get_instance().local_db.execute(
                                                add_programmed_neighbor_version_db_stmt);
                                    });
                                }
                            } else {
                                printf("Failed to update neighbor %d %s in map, skipping it\n", vni, vpc_ip.c_str());
                            }

                            i++;
                        });
                    } else {
                        printf("vpc_ip is empty\n");
                    }
                } else if (call->reply.has_securitygrouprule()) {
                    // only write security group rule to local DB, the actually ebpf map insert will
                    // happen when a port binding message is sent down. We use the port_id (vni-vpc_ip)
                    // for the SG rule's local IP, and use the securitygroupid to lookup the rest of info
                    // for sg_cidr_key_t and sg_cidr_t
                    auto security_group_id = call->reply.securitygrouprule().securitygroupid();
                    auto remote_group_id = call->reply.securitygrouprule().remotegroupid();
                    auto direction = call->reply.securitygrouprule().direction();
                    auto remote_ip_prefix = call->reply.securitygrouprule().remoteipprefix();
                    auto protocol = call->reply.securitygrouprule().protocol();
                    auto port_range_max = call->reply.securitygrouprule().portrangemax();
                    auto port_range_min = call->reply.securitygrouprule().portrangemin();
                    auto ether_type = call->reply.securitygrouprule().ethertype();
                    auto vni = call->reply.securitygrouprule().vni();
                    auto version = call->reply.securitygrouprule().version();

                    // non-empty rule
                    if ("" != security_group_id) {
                        db_client::get_instance().local_db_writer_queue.dispatch(
                                [security_group_id, remote_group_id, direction, remote_ip_prefix, protocol, port_range_max, port_range_min, &add_or_update_security_group_rule_db_stmt, ether_type, vni, version] {
                            get<0>(add_or_update_security_group_rule_db_stmt) =
                                    { security_group_id, remote_group_id, direction, remote_ip_prefix, protocol, port_range_max, port_range_min, ether_type, vni, version };
                            db_client::get_instance().local_db.execute(add_or_update_security_group_rule_db_stmt);
                        });
                        printf("Dispatched local db security group rule insert\n");
                    } else {
                        printf("security group id is empty\n");
                    }
                } else if (call->reply.has_securitygroupportbinding()) {
                    auto port_id = call->reply.securitygroupportbinding().portid();
                    auto security_group_id = call->reply.securitygroupportbinding().securitygroupid();
                    auto version = call->reply.securitygroupportbinding().version();
                    int fd = fd_security_group_ebpf_map;

                    // non-empty rule
                    if ("" != port_id && "" != security_group_id) {
                        marl::schedule([this, &i, port_id, security_group_id, version, fd,
                                        &add_or_update_security_group_port_binding_stmt, &add_programmed_security_group_port_binding_version_db_stmt] {
                            // step #0 - split the port id into vni and vpc_id, then get the security group rules based on the security group id
                            std::string delimiter = "-"; //because port_id is in the format of "vni-vpc_id"
                            std::string vni = port_id.substr(0, port_id.find(delimiter));
                            std::string vpc_ip = port_id.substr(port_id.find(delimiter) + 1);
                            // step #1 - check and store <security_group_port_binding_id, version> as <k, v> in concurrent hash map
                            std::string security_group_port_binding_id = port_id + "-" + security_group_id;
                            printf("vpc_ip is NOT empty: [%s]\n", vpc_ip.c_str());
                            bool ebpf_ignored = false;
                            bool map_updated = false;
                            int update_ct = 0, max_update_ct = 5;

                            while (!map_updated && (update_ct < max_update_ct)) {
                                printf("Inside while loop, map_updated = [%b], update_ct = [%ld], max_update_ct = [%ld]\n",
                                       map_updated, update_ct, max_update_ct);
                                auto sg_pos = security_group_rule_task_map.find(security_group_port_binding_id);
                                if (sg_pos == security_group_rule_task_map.end()) {
                                    // key not found, try insert. The function returns successful only when key not exists when inserting
                                    auto res_insert =
                                            security_group_rule_task_map.insert(security_group_port_binding_id, version);
                                    if (res_insert.second) {
                                        // means successfully inserted, done with update
                                        map_updated = true;
                                        printf("Found neighbor key in security_group_rule_task_map\n");
                                    } // 'else' means another thread already inserted before me, then it's not an insert case and next time in the loop will go to case of update
                                } else {
                                    printf("Didn't find neighbor key in security_group_rule_task_map\n");
                                    // key found, means multi neighbor versions might update at the same time
                                    int cur_ver = sg_pos->second;

                                    if (version > cur_ver) {
                                        // only update neighbor version
                                        //   1. when received (from ArionMaster) neighbor version is greater than current version in map
                                        //   2. and only if the element to update is the original element (version in 'find')
                                        if (security_group_rule_task_map.assign_if_equal(security_group_port_binding_id, version, cur_ver)) {
                                            map_updated = true;
                                        }
                                    } else {
                                        // otherwise
                                        // ignore:
                                        //   1. update concurrent hash map
                                        //   2. update ebpf map to not overwrite new data with out dated data
                                        //   3. update local db table 1 (table 1 is for local lookup) since it is an old version
                                        // update: journal table (since this skipped version is treated as programming succeeded)
                                        ebpf_ignored = true;
                                        map_updated = true;
                                    }
                                }

                                update_ct++;
                            }

                            if (map_updated) {
                                if (!ebpf_ignored) {
                                    printf("ebpf_ignored = false\n");
                                    // step 1.5 get all related security group rules.
                                    auto rows = db_client::get_instance().local_db.get_all<::SecurityGroupRule>(
                                            where(
//                                                    is_equal(
                                                            c(&::SecurityGroupRule::security_group_id) == security_group_id.c_str()
//                                                    )
                                            )
                                    );
//                                    printf("Retrieved %ld rows of security group rules with security group id == [%s]\n", rows.size(), security_group_id.c_str());
                                    int ebpf_rc = 0;
                                    /*
                                    for (auto &rule : rows) {
                                        // step #2 - sync syscall ebpf map programming with return code
                                        string remote_ip;
                                        int prefixlen = 0 ;
                                        remote_ip = rule.remote_ip_prefix.substr(0, rule.remote_ip_prefix.find("/"));
                                        prefixlen = atoi((rule.remote_ip_prefix.substr(rule.remote_ip_prefix.find("/") + 1).c_str()));

                                        struct sockaddr_in local_ip_sock, remote_ip_sock;
                                        inet_pton(AF_INET, vpc_ip.c_str(), &(local_ip_sock.sin_addr));
                                        inet_pton(AF_INET, remote_ip.c_str(), &(local_ip_sock.sin_addr));
                                        sg_cidr_key_t sg_key;
                                        sg_key.vni = atoi(vni.c_str());
                                        sg_key.prefixlen = prefixlen + 96; // 96 = ( __u32 vni; + __u16 port; + __u8  direction; + __u8  protocol; + __u32 local_ip; )
                                        sg_key.remote_ip = remote_ip_sock.sin_addr.s_addr;
                                        sg_key.local_ip = local_ip_sock.sin_addr.s_addr;
                                        sg_key.direction = rule.direction == "out" ? 0 : 1; // going out is 0 and coming in is 1

                                        if (rule.protocol == "TCP") {
                                            sg_key.protocol = IPPROTO_TCP;
                                        } else if (rule.protocol == "UDP") {
                                            sg_key.protocol = IPPROTO_UDP;
                                        } else {
                                            sg_key.protocol = IPPROTO_NONE;
                                        }

                                        sg_key.port = rule.port_range_min; //TODO: see if we should use this or other fields

                                        sg_cidr_t sg_value;
                                        sg_value.sg_id = 1;
                                        sg_value.action = 1; // 1 for allow and other values for drop

                                        int single_ebpf_rc = bpf_map_update_elem(fd, &sg_key, &sg_value, BPF_ANY);
                                        if (single_ebpf_rc != 0) {
                                            ebpf_rc = single_ebpf_rc;
                                            printf("Tried to insert into sg rule ebpf map, but got RC: [%ld], errno: [%s]\n", single_ebpf_rc, std::strerror(errno));
                                        }
                                        // also put in local in memory cache
                                        db_client::get_instance().sg_rule_cache[sg_key] = sg_value;//.insert(epkey, ep);
                                        printf("GPPC: Inserted this neighbor into map: vip: %s, vni: %s\n", vpc_ip.c_str(), vni.c_str());

                                    }
                                    // step #3 - async call to write/update to local db table
                                    db_client::get_instance().local_db_writer_queue.dispatch([security_group_id, port_id, version, &add_or_update_security_group_port_binding_stmt] {
                                        get<0>(add_or_update_security_group_port_binding_stmt) = { port_id, security_group_id };
                                        db_client::get_instance().local_db.execute(add_or_update_security_group_port_binding_stmt);
                                    });
                                    printf("Dispatched local db neighbor insert\n");

                                    // step #4 (case 1) - when ebpf programming not ignored, write to table 2 (programming journal) when programming succeeded
                                    if (0 == ebpf_rc) {
                                        db_client::get_instance().local_db_writer_queue.dispatch([version, &add_programmed_security_group_port_binding_version_db_stmt] {
                                            get<0>(add_programmed_security_group_port_binding_version_db_stmt) = { version };
                                            db_client::get_instance().local_db.execute(
                                                    add_programmed_security_group_port_binding_version_db_stmt);
                                        });
                                    } else {
                                        printf("ebpf_rc = [%ld], this version isn't finished, NOT updating the local DB.\n", ebpf_rc);
                                    }
                                    printf("Dispatched local db journal insert\n");
                                     */

                                } else {
                                    printf("ebpf_ignored = true\n");
                                    // step #4 (case 2) - always write to local db table 2 (programming journal) when version intended ignored (no need to program older version)
                                    db_client::get_instance().local_db_writer_queue.dispatch([version, &add_programmed_security_group_port_binding_version_db_stmt] {
                                        get<0>(add_programmed_security_group_port_binding_version_db_stmt) = { version };
                                        db_client::get_instance().local_db.execute(
                                                add_programmed_security_group_port_binding_version_db_stmt);
                                    });
                                }
                            } else {
                                printf("Failed to update neighbor %d %s in map, skipping it\n", vni.c_str(), vpc_ip.c_str());
                            }

                            i++;
                        });
                    } else {
                        printf("port_id [%s] or security_group_id: [%s] is empty\n", port_id.c_str(), security_group_id.c_str());
                    }                } else {
                    printf("This reply doesn't have a neighbor rule, a security group rule, or a security group port binding\n");
                }

            }
        } else {
            printf("NOT okay\n");
        }
    }
}

void ArionMasterWatcherImpl::ConnectToArionMaster() {
    grpc::ChannelArguments args;
    // Channel does a keep alive ping every 10 seconds;
    args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 10000);
    // If the channel does receive the keep alive ping result in 20 seconds, it closes the connection
    args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);
    // Allow keep alive ping even if there are no calls in flight
    args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);

    chan_ = grpc::CreateCustomChannel(server_address + ":" + server_port,
                                      grpc::InsecureChannelCredentials(), args);
    stub_ = Watch::NewStub(chan_);

    printf("After initiating a new sub to connect to the Arion Master: %s\n", (server_address + ":" + server_port).c_str());
}

void ArionMasterWatcherImpl::RunClient(std::string ip, std::string port, std::string group, std::string endpoints_table, std::string security_group_rules_table) {
    printf("Running a grpc client in a separate thread id: %ld\n", std::this_thread::get_id());

    server_address = ip;
    server_port = port;
    group_id = group;
    table_name_neighbor_ebpf_map = endpoints_table;
    table_name_sg_ebpf_map = security_group_rules_table;

    // Retrieve neighbor's ebpf map fd (handle)
    fd_neighbor_ebpf_map = bpf_obj_get(table_name_neighbor_ebpf_map.c_str());
//    if (fd_neighbor_ebpf_map < 0) {
//        printf("Failed to get xdp neighbor endpoint map fd, exiting\n");
//        return;
//    } else {
//        printf("Got xdp neighbor endpoint map fd %d\n", fd_neighbor_ebpf_map);
//    }

    // check if security group ebpf map exists, and create it if it doesn't

    fd_security_group_ebpf_map = bpf_obj_get(table_name_sg_ebpf_map.c_str());

    if (fd_security_group_ebpf_map < 0) {
        printf("Creating security_group_ebpf_map manually\n");

        size_t key_size_security_group;
        key_size_security_group = sizeof(sg_cidr_key_t);

        printf("Key size: %ld, value size: %ld\n", key_size_security_group, sizeof(sg_cidr_t));
        fd_security_group_ebpf_map = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE,
                                                    key_size_security_group,
                       sizeof(sg_cidr_t),
                       999,  // need to change it to a bigger number later.
                       BPF_F_NO_PREALLOC);

        if (fd_security_group_ebpf_map <= 0) {
            printf("Tried to manually create security group map, but failed with fd: %ld, and error no: %s, returning\n",
                   fd_security_group_ebpf_map, std::strerror(errno));
            exit(-1);
        }
        printf("Manually created security group map with fd: %ld, returning\n", fd_security_group_ebpf_map);

    }

    // Find lkg version to reconcile/sync from server
    int rev_lkg = db_client::get_instance().FindLKGVersion();
    printf("Found last known good version: %d from local db to sync from server\n", rev_lkg);
    db_client::get_instance().FillEndpointCacheFromDB();
    this->ConnectToArionMaster();
    grpc::CompletionQueue cq;
    // This vector includes the Arion Requests that will be sent to Arion Master
    vector<ArionWingRequest *> arion_request_vector;
    ArionWingRequest neighbor_watch_req;
    neighbor_watch_req.set_map("NeighborRule");
    neighbor_watch_req.set_group(group_id);
    neighbor_watch_req.set_rev(rev_lkg);

    ArionWingRequest security_group_rule_watch_req;
    security_group_rule_watch_req.set_map("SecurityGroupRule");
    // set version 0 for now.
    security_group_rule_watch_req.set_rev(0);
    // set empty group rule for now.
    security_group_rule_watch_req.set_group("");
    arion_request_vector.emplace_back(&neighbor_watch_req);
    arion_request_vector.emplace_back(&security_group_rule_watch_req);
    this->RequestArionMaster(&arion_request_vector, &cq);
}
