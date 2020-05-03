# NetFuzz
NetFuzz is a fiber-based networking fuzzer for testing the reliable UDP transports. It exploits green concurrency to simulate connections under various conditions but preserving the order of execution. The application was created for testing and debugging a proprietary networking library, but it also supports [ENet](https://github.com/nxrighthere/ENet-CSharp) as an open-source alternative.

Commands
--------
`--library [identifier]` Networking library identifier

`--clients [number]` Number of simulated clients (256 by default)

`--port [number]` Port number for connection establishment (9500 by default)
