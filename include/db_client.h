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
#include "dispatch_queue.h"

struct Neighbor {
    int vni;
    std::string vpc_ip;
    std::string host_ip;
    std::string vpc_mac;
    std::string host_mac;
    int version;
}; // local db table 1 - neighbor info table that stores neighbors received from ArionMaster

struct ProgrammingState {
    int version;
}; // local db table 2 - neighbor ebpf programming state with version

std::string g_local_db_path = "/var/local/arion/arion_wing.db";

// Schema definition (create DB if not exists) or retrieved handle (get DB if exists already) of local db
auto local_db = sqlite_orm::make_storage(g_local_db_path,
                                         sqlite_orm::make_table("neighbor",
                                                                sqlite_orm::make_column("vni", &Neighbor::vni),
                                                                sqlite_orm::make_column("vpc_ip", &Neighbor::vpc_ip),
                                                                sqlite_orm::make_column("host_ip", &Neighbor::host_ip),
                                                                sqlite_orm::make_column("vpc_mac", &Neighbor::vpc_mac),
                                                                sqlite_orm::make_column("host_mac", &Neighbor::host_mac),
                                                                sqlite_orm::make_column("version", &Neighbor::version),
                                                                sqlite_orm::primary_key(&Neighbor::vni, &Neighbor::vpc_ip)
                                         ),
                                         sqlite_orm::make_table("journal",
                                                                sqlite_orm::make_column("version", &ProgrammingState::version),
                                                                sqlite_orm::primary_key(&ProgrammingState::version)
                                         )
);

// Create local db writer single thread execution queue
dispatch_queue local_db_writer_queue("Local db background write queue", 1);
