# nldecap
*Pretty-printing for netlink monitoring device captures.*

`nldecap` allows you to see what's happening over the netlink interface, in a human-readable way.

## Requirements
* Python 2.7
* A recent [pyroute2](https://github.com/svinota/pyroute2)

## Basic Usage
`./nldecap.py <pcap file> [filter [filter ...]]`

See `./nldecap.py -h` for all options and their help.

### The pcap file
`nldecap` takes a pcap file as its first argument, or `-` for standard input.

This file is typically obtained by capturing on a [nlmon](#nlmon-interfaces) interface with `tcpdump(8)`, although the `-` syntax allows reading directly tcpdump's piped output, like this:
```shell
# tcpdump -i nlmon0 -U -w - | ./nldecap.py -
```
The `-U` argument to `tcpdump` makes its packet output unbuffered, which means packets will be displayed immediately upon reception and not after a buffer-induced delay.

### Filters
Filters can be specified as positional arguments after the filename to limit the displayed message types. These map directly to pyroute2's message types.

Valid filters at the time of writing are `ifinfmsg`, `ifaddrmsg`, `ndtmsg`, `tcmsg`, `fibmsg`, `ndmsg`, `rtmsg`.

## `nlmon` interfaces

Netlink Monitoring interfaces allow capturing traffic over netlink sockets with traditional packet capture tools.

This makes them very useful for netlink-related troubleshooting, and they're also easy to setup:
```shell
# ip link add nlmon0 type nlmon
# ip link set nlmon0 up
```

## TODO
* Support more Python versions
* Determine minimal pyroute2 version
* More tests

## In action
```shell
$ # Using the builtin tree-like display
$ ./nldecap.py ipr.cap
[packet 1] message 1 (rtmsg)
├─family : 2
├─dst_len : 0
├─proto : 0
├─tos : 0
├─event : 'RTM_GETROUTE'
├─header
│ ├─pid : 0
│ ├─length : 40
│ ├─flags : 769
│ ├─error : None
│ ├─type : 26
│ └─sequence_number : 1497801523
├─flags : 0
├─attrs
│ ├[0] RTA_UNSPEC : None
│ └[1] UNKNOWN
│   └─header
│     ├─length : 8
│     └─type : 29
├─table : 0
├─src_len : 0
├─type : 0
└─scope : 0

$ # Using the pprint display
$ ./nldecap.py ipr.cap -p
[packet 1] message 1 (rtmsg)
{'attrs': [('RTA_UNSPEC', None),
           ('UNKNOWN', {'header': {'length': 8, 'type': 29}})],
 'dst_len': 0,
 'event': 'RTM_GETROUTE',
 'family': 2,
 'flags': 0,
 'header': {'error': None,
            'flags': 769,
            'length': 40,
            'pid': 0,
            'sequence_number': 1497801523,
            'type': 26},
 'proto': 0,
 'scope': 0,
 'src_len': 0,
 'table': 0,
 'tos': 0,
 'type': 0} 

```
