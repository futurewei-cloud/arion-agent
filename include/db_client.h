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

using namespace sqlite_orm;

struct Neighbor {
    int vni;
    std::string vpc_ip;
    std::string host_ip;
    std::string vpc_mac;
    std::string host_mac;
    int version;
}; // local db table 1 - neighbor info table that stores the latest neighbors (if there are version updates per neighbor) received from ArionMaster

struct ProgrammingState {
    int version;
}; // local db table 2 - neighbor ebpf programmed version

std::string g_local_db_path = "/var/local/arion/arion_wing.db";

// Schema definition (create DB if not exists) or retrieved handle (get DB if exists already) of local db
auto local_db = make_storage(g_local_db_path,
                             make_table("neighbor",
                                        make_column("vni", &Neighbor::vni),
                                        make_column("vpc_ip", &Neighbor::vpc_ip),
                                        make_column("host_ip", &Neighbor::host_ip),
                                        make_column("vpc_mac", &Neighbor::vpc_mac),
                                        make_column("host_mac", &Neighbor::host_mac),
                                        make_column("version", &Neighbor::version),
                                        primary_key(&Neighbor::vni, &Neighbor::vpc_ip)
                             ),
                             make_table("journal",
                                        make_column("version", &ProgrammingState::version),
                                        primary_key(&ProgrammingState::version)
                             )
);

// Create local db writer single thread execution queue
dispatch_queue local_db_writer_queue("Local db background write queue", 1);

static int FindLKGVersion() {
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

    using als_mo = alias_a<ProgrammingState>;
    using als_mi = alias_b<ProgrammingState>;
    auto ver_gaps = local_db.select(alias_column<als_mo>(&ProgrammingState::version),
                                    from<als_mo>(),
                                    where(not exists(
                                          select(0 - c(alias_column<als_mi>(&ProgrammingState::version)),
                                                 from<als_mi>(),
                                                 where(is_equal(c(alias_column<als_mo>(&ProgrammingState::version)) + 1, alias_column<als_mi>(&ProgrammingState::version)))
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
}
