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

void ArionMasterWatcherImpl::RequestNeighborRules(ArionWingRequest *request,
                                                  grpc::CompletionQueue *cq) {
    grpc::ClientContext ctx;
    arion::schema::NeighborRule reply;

    // prepared statements for better performance of db writing in completion queue
    auto add_or_update_neighbor_db_stmt = db_client::get_instance().local_db.prepare(replace(Neighbor{ 0, "", "", "", "", 0 }));
    auto add_programmed_version_db_stmt = db_client::get_instance().local_db.prepare(insert(ProgrammingState{ 0 }));

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
                call->stream->Write(*request, (void*)tag_watch);

                write_done = true;
            } else {
                call->stream->Read(&call->reply, got_tag);
                auto vni = call->reply.tunnel_id();
                auto vpc_ip = call->reply.ip();
                auto vpc_mac = call->reply.mac();
                auto host_ip = call->reply.hostip();
                auto host_mac = call->reply.hostmac();
                auto ver = call->reply.version();
                int fd = fd_neighbor_ebpf_map;

                // non-empty rule
                if ("" != vpc_ip) {
                    marl::schedule([this, &i, vni, vpc_ip, vpc_mac, host_ip, host_mac, ver, fd,
                                    &add_or_update_neighbor_db_stmt, &add_programmed_version_db_stmt] {
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

                                int ebpf_rc = 0;//bpf_map_update_elem(fd, &epkey, &ep, BPF_ANY);
                                // also put in local in memory cache
                                db_client::get_instance().endpoint_cache.insert(epkey, ep);
                                printf("GPPC: Inserted this neighbor into map: vip: %s, vni: %d\n", vpc_ip.c_str(), vni);
                                // step #3 - async call to write/update to local db table 1
                                db_client::get_instance().local_db_writer_queue.dispatch([vni, vpc_ip, host_ip, vpc_mac, host_mac, ver, &add_or_update_neighbor_db_stmt] {
                                    get<0>(add_or_update_neighbor_db_stmt) = { vni, vpc_ip, host_ip, vpc_mac, host_mac, ver };
                                    db_client::get_instance().local_db.execute(add_or_update_neighbor_db_stmt);
                                });
                                printf("Dispatched local db neighbor insert\n");
                                // step #4 (case 1) - when ebpf programming not ignored, write to table 2 (programming journal) when programming succeeded
                                if (0 == ebpf_rc) {
                                    db_client::get_instance().local_db_writer_queue.dispatch([ver, &add_programmed_version_db_stmt] {
                                        get<0>(add_programmed_version_db_stmt) = { ver };
                                        db_client::get_instance().local_db.execute(add_programmed_version_db_stmt);
                                    });
                                }
                                printf("Dispatched local db journal insert\n");
                            } else {
                                printf("ebpf_ignored = true\n");
                                // step #4 (case 2) - always write to local db table 2 (programming journal) when version intended ignored (no need to program older version)
                                db_client::get_instance().local_db_writer_queue.dispatch([ver, &add_programmed_version_db_stmt] {
                                    get<0>(add_programmed_version_db_stmt) = { ver };
                                    db_client::get_instance().local_db.execute(add_programmed_version_db_stmt);
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

void ArionMasterWatcherImpl::RunClient(std::string ip, std::string port, std::string group, std::string table) {
    printf("Running a grpc client in a separate thread id: %ld\n", std::this_thread::get_id());

    server_address = ip;
    server_port = port;
    group_id = group;
    table_name_neighbor_ebpf_map = table;

    // Retrieve neighbor's ebpf map fd (handle)
    fd_neighbor_ebpf_map = bpf_obj_get(table_name_neighbor_ebpf_map.c_str());
//    if (fd_neighbor_ebpf_map < 0) {
//        printf("Failed to get xdp neighbor endpoint map fd, exiting\n");
//        return;
//    } else {
//        printf("Got xdp neighbor endpoint map fd %d\n", fd_neighbor_ebpf_map);
//    }

    // Create (if db not exists) or connect (if db exists already) to local db
    db_client::get_instance().local_db.sync_schema();

    // Find lkg version to reconcile/sync from server
    int rev_lkg = db_client::get_instance().FindLKGVersion();
    printf("Found last known good version: %d from local db to sync from server\n", rev_lkg);
    db_client::get_instance().FillEndpointCacheFromDB();
    this->ConnectToArionMaster();
    grpc::CompletionQueue cq;
    ArionWingRequest watch_req;
    watch_req.set_group(group_id);
    watch_req.set_rev(rev_lkg);
    this->RequestNeighborRules(&watch_req, &cq);
}
