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

#include "dispatch_queue.h"

dispatch_queue::dispatch_queue(std::string name, size_t thread_cnt) :
        name_{std::move(name)}, threads_(thread_cnt) {
    printf("Creating dispatch queue: %s\n", name_.c_str());
    printf("Dispatch threads: %zu\n", thread_cnt);

    for (size_t i = 0; i < threads_.size(); i++) {
        threads_[i] = std::thread(&dispatch_queue::dispatch_thread_handler, this);
    }
}

dispatch_queue::~dispatch_queue() {
    printf("Destructor: Destroying dispatch threads...\n");

    // Signal to dispatch threads that it's time to wrap up
    std::unique_lock<std::mutex> lock(lock_);
    quit_ = true;
    cv_.notify_all();
    lock.unlock();

    // Wait for threads to finish before we exit
    for (size_t i = 0; i < threads_.size(); i++) {
        if (threads_[i].joinable()) {
            printf("Destructor: Joining thread %zu until completion\n", i);
            threads_[i].join();
        }
    }
}

void dispatch_queue::dispatch(const fp_t& op) {
    std::unique_lock<std::mutex> lock(lock_);
    q_.push(op);
    cv_.notify_one();
}

void dispatch_queue::dispatch(fp_t&& op) {
    std::unique_lock<std::mutex> lock(lock_);
    q_.push(std::move(op));
    cv_.notify_one();
}

void dispatch_queue::dispatch_thread_handler(void) {
    std::unique_lock<std::mutex> lock(lock_);

    do {
        // Wait until we have data or a quit signal
        cv_.wait(lock, [this] {
                return (q_.size() || quit_);
        });

        // after wait, we own the lock
        if (!quit_ && q_.size()) {
            auto op = std::move(q_.front());
            q_.pop();

            // unlock now that we're done messing with the queue
            lock.unlock();
            op();
            lock.lock();
        }
    } while(!quit_);
}
