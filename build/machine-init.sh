#!/bin/bash

# MIT License
# Copyright(c) 2022 Futurewei Cloud
#
#     Permission is hereby granted,
#     free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction,
#     including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and / or sell copies of the Software, and to permit persons
#     to whom the Software is furnished to do so, subject to the following conditions:
#
#     The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

BUILD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
echo "build path is $BUILD"

rm -rf /var/local/git
mkdir -p /var/local/git

echo "1--- installing common dependencies ---" && \
    apt-get update -y && apt-get install -y \
    rpcbind \
    rsyslog \
    build-essential \
    make \
    g++ \
    unzip \
    cmake \
    llvm-9 \
    libfmt-dev \
    libelf-dev \    #for libelf.a
    linux-tools-generic \         #for bpftool
    linux-cloud-tools-generic \   #for bpftool
    libsqlite3-dev \              #for sqlite3 lib
    doxygen \
    zlib1g-dev \
    libssl-dev \
    libboost-program-options-dev \
    libboost-all-dev \
    iproute2  \
    net-tools \
    iputils-ping \
    ethtool \
    curl \
    python3 \
    python3-pip \
    netcat \
    libcmocka-dev \
    lcov \
    git \
    autoconf \
    automake \
    dh-autoreconf \
    pkg-config \
    libtool \
    wget \
    uuid-dev \
    libgoogle-glog-dev \
    libevent \
    libtool \
    lz4 \
    lzma \
    openssl \
    snappy \
    xz \
    zlib
pip3 install httpserver netaddr

echo "2--- installing grpc dependencies ---" && \
    apt-get update -y && apt-get install -y \
    cmake libssl-dev \
    autoconf git pkg-config \
    automake libtool make g++ unzip 

# installing grpc and its dependencies
GRPC_RELEASE_TAG="v1.24.x"
echo "3--- cloning grpc repo ---" && \
    git clone -b $GRPC_RELEASE_TAG https://github.com/grpc/grpc /var/local/git/grpc && \
    cd /var/local/git/grpc && \
    git submodule update --init && \
    echo "--- installing c-ares ---" && \
    cd /var/local/git/grpc/third_party/cares/cares && \
    git fetch origin && \
    git checkout cares-1_15_0 && \
    mkdir -p cmake/build && \
    cd cmake/build && \
    cmake -DCMAKE_BUILD_TYPE=Release ../.. && \
    make -j4 install && \
    cd ../../../../.. && \
    rm -rf third_party/cares/cares && \
    echo "--- installing protobuf ---" && \
    cd /var/local/git/grpc/third_party/protobuf && \
    mkdir -p cmake/build && \
    cd cmake/build && \
    cmake -Dprotobuf_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release .. && \
    make -j4 install && \
    cd ../../../.. && \
    rm -rf third_party/protobuf && \
    echo "--- installing grpc ---" && \
    cd /var/local/git/grpc && \
    mkdir -p cmake/build && \
    cd cmake/build && \
    cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DgRPC_PROTOBUF_PROVIDER=package -DgRPC_ZLIB_PROVIDER=package -DgRPC_CARES_PROVIDER=package -DgRPC_SSL_PROVIDER=package -DCMAKE_BUILD_TYPE=Release ../.. && \
    make -j4 install && \
    echo "--- installing google test ---" && \
    cd /var/local/git/grpc/third_party/googletest && \
    cmake -Dgtest_build_samples=ON -DBUILD_SHARED_LIBS=ON . && \
    make && \
    make install && \
    rm -rf /var/local/git/grpc && \
    cd ~

echo "4--- installing marl ---" && \
    mkdir -p /var/local/git/marl && \
    cd /var/local/git/marl && \
    git clone https://github.com/google/marl.git && \
    cd /var/local/git/marl/marl && \
	  git submodule update --init && \
	  mkdir /var/local/git/marl/marl/build && \
	  cd /var/local/git/marl/marl/build && \
	  cmake .. -DMARL_BUILD_EXAMPLES=1 -DMARL_BUILD_TESTS=1 && \
    make && \
    cd ~

echo "5--- installing ebpf dependencies ---" && \
    cd /var/local/git && \
    git clone https://github.com/futurewei-cloud/zeta && \
    cd zeta && \
    ./build.sh && \
    cd ~

echo "6--- installing sqlite3 database ---" && \
    wget https://www.sqlite.org/2022/sqlite-autoconf-3390200.tar.gz && \
    tar xvfz ./sqlite-autoconf-3390200.tar.gz && \
    cd ./sqlite-autoconf-3390200 && \
    ./configure --prefix=/usr/local && \
    make && \
    make install && \
    cd ~

echo "7--- installing sqlite orm lib dependencies ---" && \
    cd /var/local/git && \
    git clone https://github.com/fnc12/sqlite_orm.git sqlite_orm && \
    cd sqlite_orm && \
    cmake -B build && \
    sudo cmake --build build --target install && \
    cd ~

echo "8--- installing double conversion for folly ---" && \
    cd /var/local/git && \
    git clone https://github.com/google/double-conversion.git && \
    cd double-conversion && \
    cmake -DBUILD_SHARED_LIBS=ON . && \
    make && \
    sudo make install && \
    cd ~

echo "9--- installing folly lib for concurrent hashmap ---" && \
    cd /var/local/git && \
    git clone https://github.com/facebook/folly.git && \
    cd folly && \
    mkdir _build && \
    cd _build && \
    cmake .. && \
    make && \
    sudo make install && \
    cd ~
