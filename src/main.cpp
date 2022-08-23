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

#include "grpc_client.h"

#include <thread>
#include <chrono>
#include <unistd.h> /* for getopt */
#include <grpcpp/grpcpp.h>
#include <cmath>

#include "marl/defer.h"
#include "marl/event.h"
#include "marl/scheduler.h"
#include "marl/waitgroup.h"

using namespace std;
using std::string;

// Defines
#define LOGNAME "ArionAgent"
static char EMPTY_STRING[] = "";

// Global variables
std::thread *g_grpc_client_thread = NULL;
ArionMasterWatcherImpl *g_grpc_client = NULL;

string g_arion_master_address = EMPTY_STRING;
string g_arion_master_port = "9090";
string g_arion_neighbor_table = "/sys/fs/bpf/endpoints_map";
//TODO: read from goalstate
string g_arion_group = "group1";

// total time for goal state update in microseconds
std::atomic_ulong g_total_update_neighbor_time(0);

bool g_debug_mode = false;
int processor_count = std::thread::hardware_concurrency();
/*
  From previous tests, we found that, for x number of cores,
  it is more efficient to set the size of both thread pools
  to be x * (2/3), which means the total size of the thread pools
  is x * (4/3). For example, for a host with 24 cores, we would
  set the sizes of both thread pools to be 16.
*/
int thread_pools_size = (processor_count == 0) ? 1 : ((ceil(1.3 * processor_count)) / 2);

static void cleanup() {
    printf("%s", "Program exiting, cleaning up...\n");

    // optional: delete all global objects allocated by libprotobuf.
    google::protobuf::ShutdownProtobufLibrary();

    // stop the grpc client
    if (g_grpc_client != NULL) {
        delete g_grpc_client;
        g_grpc_client = NULL;
        printf("%s", "Cleaned up grpc client.\n");
    } else {
        printf("%s", "Unable to delete grpc client pointer since it is null.\n");
    }

    if (g_grpc_client_thread != NULL) {
        delete g_grpc_client_thread;
        g_grpc_client_thread = NULL;
        printf("%s", "Cleaned up grpc client thread.\n");
    } else {
        printf("%s", "Unable to call delete grpc client thread pointer since it is null.\n");
    }
}

// function to handle ctrl-c and kill process
static void signal_handler(int sig_num) {
    printf("Caught signal: %d\n", sig_num);

    // perform all the necessary cleanup here
    cleanup();
    exit(sig_num);
}

int main(int argc, char *argv[]) {
    int option;
    int rc = 0;

    printf("%s", "Arion Agent started...\n");

    // Register input key signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while ((option = getopt(argc, argv, "a:p:g:d")) != -1) {
        switch (option) {
        case 'a':
            g_arion_master_address = optarg;
            break;
        case 'p':
            g_arion_master_port = optarg;
            break;
        case 'g':
            g_arion_group = optarg;
            break;
        case 'd':
            g_debug_mode = true;
            break;
        default: //the '?' case when the option is not recognized
            printf("Usage: %s\n"
                   "\t\t[-a Arion Master Server IP Address]\n"
                   "\t\t[-p Arion Master Server Port]\n"
                   "\t\t[-g Arion Wing Group Id]\n"
                   "\t\t[-d Enable debug mode]\n",
                   argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // Create marl scheduler using all the logical processors available to the process.
    // Bind this scheduler to the main thread so we can call marl::schedule()
    marl::Scheduler::Config cfg_bind_hw_cores;
    cfg_bind_hw_cores.setWorkerThreadCount(thread_pools_size * 2);
    marl::Scheduler task_scheduler(cfg_bind_hw_cores);
    task_scheduler.bind();
    defer(task_scheduler.unbind());

    // Create a separate thread to run the grpc client of watching Arion Master
    g_grpc_client = new ArionMasterWatcherImpl();
    marl::schedule([=] {
        g_grpc_client->RunClient(g_arion_master_address,
                                 g_arion_master_port,
                                 g_arion_group,
                                 g_arion_neighbor_table);
    });

    pause();
    cleanup();

    return rc;
}
