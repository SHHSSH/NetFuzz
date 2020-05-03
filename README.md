# NetFuzz
NetFuzz is a fiber-based networking fuzzer for testing the reliable UDP transports. The application was created for stress testing and debugging a proprietary networking library, but it also supports [ENet](https://github.com/nxrighthere/ENet-CSharp) as an open-source alternative. It exploits green concurrency to simulate connections under various conditions but preserving the order of execution.

Commands
--------
`--library [identifier]` Networking library identifier

`--clients [number]` Number of simulated clients (256 by default)

`--port [number]` Port number for connection establishment (9500 by default)
