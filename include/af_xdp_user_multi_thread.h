//
// Created by ubuntu on 10/4/22.
//

#ifndef ARIONAGENT_AF_XDP_USER_MULTI_THREADED_H
#define ARIONAGENT_AF_XDP_USER_MULTI_THREADED_H

#include "logger.h"
#include <bpf.h>
#include <xsk.h>
#include <errno.h>
#include <string>
#ifdef __cplusplus
extern "C"
{
#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "common_libbpf.h"
}
#endif
static const char *__d__ = "AF_XDP kernel bypass example multi threaded\n";

class af_xdp_user_multi_thread {
public:
    af_xdp_user_multi_thread() {
        printf("%s", "Start of multithread af_xdp userspace program.");
    }
    static void* run_af_xdp_multi_threaded(void* args/*std::string table_name_neighbor_ebpf_map*/);
private:

};

#endif //ARIONAGENT_AF_XDP_USER_H
