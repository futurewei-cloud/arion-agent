# arion-agent
Arion Agent: Local Network Agent on each Arion Wing


## Compile

    ./build/build.sh


## Sample command to start ArionAgent

    sudo ./build/bin/ArionAgent -a 10.0.0.4 -p 9090 -g 1 (-a is the ArionMaster grpc server IP, -p is the server port, and -g is the group that this wing belongs to)


## Performance benchmark

[Benchmark](./PERFORMANCE.md)
