//
// Created by ubuntu on 10/4/22.
//

#ifndef ARIONAGENT_AF_XDP_USER_H
#define ARIONAGENT_AF_XDP_USER_H

#include "logger.h"
#include <bpf.h>
#include <xsk.h>
#include <errno.h>

#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "common_libbpf.h"

static const char *__doc__ = "AF_XDP kernel bypass example\n";

class af_xdp_user {
public:
    af_xdp_user() {
        printf("%s", "Start of af_xdp userspace program.");
    }
    void run_af_xdp(int argc, char *argv[]);
private:

};

#endif //ARIONAGENT_AF_XDP_USER_H