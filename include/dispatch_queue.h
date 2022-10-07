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

#include <thread>
#include <functional>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <queue>
#include <mutex>
#include <string>
#include <condition_variable>

class dispatch_queue {
    typedef std::function<void(void)> fp_t;

public:
    dispatch_queue(std::string name, size_t thread_cnt = 1);
    ~dispatch_queue();

    // dispatch and copy
    void dispatch(const fp_t& op);
    // dispatch and move
    void dispatch(fp_t&& op);

    // Deleted operations
    dispatch_queue(const dispatch_queue& rhs) = delete;
    dispatch_queue& operator=(const dispatch_queue& rhs) = delete;
    dispatch_queue(dispatch_queue&& rhs) = delete;
    dispatch_queue& operator=(dispatch_queue&& rhs) = delete;

private:
    std::string name_;
    std::mutex lock_;
    std::vector<std::thread> threads_;
    std::queue<fp_t> q_;
    std::condition_variable cv_;
    bool quit_ = false;

    void dispatch_thread_handler(void);
};
