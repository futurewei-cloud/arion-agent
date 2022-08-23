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
#include "grpc_client.h"
#include "xdp/trn_datamodel.h"

using namespace arion::schema;

void ArionMasterWatcherImpl::RequestNeighborRules(ArionWingRequest *request,
                                                  grpc::CompletionQueue *cq) {
    grpc::ClientContext ctx;
    arion::schema::NeighborRule reply;

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
                //auto arionwing_group = call->reply.arionwing_group();
                //auto rev = call->reply.version();
                int fd = fd_neighbor_ebpf_map;

                if ("" != vpc_ip) { //non-empty rule
                    marl::schedule([this, &i, vni, vpc_ip, vpc_mac, host_ip, host_mac, fd, start] {
                        endpoint_key_t epkey;
                        epkey.vni = vni;
                        struct sockaddr_in ep_ip;
                        inet_pton(AF_INET, vpc_ip.c_str(), &(ep_ip.sin_addr));
                        epkey.ip = ep_ip.sin_addr.s_addr;

                        endpoint_t ep;
                        struct sockaddr_in ep_hip;
                        inet_pton(AF_INET, host_ip.c_str(), &(ep_hip.sin_addr));
                        ep.hip = ep_hip.sin_addr.s_addr;

                        // handle vpc mac address
                        std::sscanf(vpc_mac.c_str(),
                                    "%02x:%02x:%02x:%02x:%02x:%02x",
                                    &ep.mac[0], &ep.mac[1], &ep.mac[2],
                                    &ep.mac[3], &ep.mac[4], &ep.mac[5]);

                        // handle host mac address
                        std::sscanf(host_mac.c_str(),
                                    "%02x:%02x:%02x:%02x:%02x:%02x",
                                    &ep.hmac[0], &ep.hmac[1], &ep.hmac[2],
                                    &ep.hmac[3], &ep.hmac[4], &ep.hmac[5]);

                        int rc = bpf_map_update_elem(fd, &epkey, &ep, BPF_ANY);

                        i++;
                    });
                }
            }
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

    fd_neighbor_ebpf_map = bpf_obj_get(table_name_neighbor_ebpf_map.c_str());
    if (fd_neighbor_ebpf_map < 0) {
        printf("Failed to get xdp neighbor endpoint map fd\n");
    } else {
        printf("Got xdp neighbor endpoint map fd %d\n", fd_neighbor_ebpf_map);
    }

    this->ConnectToArionMaster();
    // TODO: read from db and starting watcher from last known good revision
    grpc::CompletionQueue cq;
    ArionWingRequest watch_req;
    watch_req.set_group(group_id);
    watch_req.set_rev(1);
    this->RequestNeighborRules(&watch_req, &cq);
}
