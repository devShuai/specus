"""Generate peer-egress-macos-routes-v1.json.

macOS route takeover reads the table with `netstat -rn -f inet` and changes it with `route`. Every
fixture below was captured from a real macOS 26.6.2 machine, and three of the captures changed the
design rather than confirming it.

First: `route` returns 0 when it fails. Adding a prefix that already exists prints
"add net 203.0.113.0: gateway 192.168.64.1: File exists" and exits 0; so does deleting a prefix that
is not there, and so does pointing a route at an interface with no address. An implementation that
trusted the exit status would report a failed install as a success, and the installer would then
believe a rule was in force while the traffic it was meant to capture went out of the physical
interface. What separates success from failure is that `route` writes nothing to stderr when it
works -- across every successful mutation sampled here -- so the classification is keyed on stderr
being non-empty rather than on any list of error texts. That also means it does not need to know
every error the routing socket can return, which is unbounded: it is strerror of whatever the kernel
said.

Second: `route -n add -net 203.0.113.0/33 192.168.64.1` is accepted. It prints
"add net 203.0.113.0: gateway 192.168.64.1", exits 0, and installs `128.0/1` -- half of the IPv4
address space, pointed at the gateway. Nothing in the output says so; only the table does. On
Windows the equivalent argument was refused by New-NetRoute, so validating the prefix before running
anything was defence in depth. Here it is the only defence there is.

Third: the readings are cheap. `netstat -rn -f inet` has a median of 25 ms on the sampling machine
and `route -n get` 26 ms, against 3 ms for /usr/bin/true. The Windows side caches one read of the
whole table for five seconds because PowerShell costs 419 ms per query and a plan of twenty prefixes
would otherwise spend eight seconds asking; twenty reads here cost half a second. So macOS does not
cache: the cache would buy a saving that is not there in exchange for a window in which the answer
is stale. The measurement is what decides it, which is why the numbers are in this file.

Two further things the captures settled. The output is not localised -- the same commands under
zh_CN, ja_JP and de_DE produce output identical to the C locale, byte for byte -- so parsing the
keys is safe here in a way it is not on Windows, where the same command prints Chinese column
headers under one console code page. And `route -n get` never reports a gateway for a destination
that is on-link, not even for the gateway's own address, which has a link-level entry in the table
with a MAC address in it; the gateway field is absent rather than holding something that is not an
address.

The expectations come from the reference implementations in this file, not from any of the three
runtimes.
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

# Captured on a real macOS machine by tools/protocol/sample_macos_routes.py, which was
# deleted afterwards. Keyed by the capture name, so every fixture below says where it
# came from: the argv is the command that produced it and the exit status is what it
# returned.
#
# This block is machine-written from the capture records. Nothing here was retyped.
SAMPLED = {
    'provenance-sw-vers': {
        "argv": ['sw_vers'],
        "exit": 0,
        "stdout": 'ProductName:\t\tmacOS\nProductVersion:\t\t26.6.2\nBuildVersion:\t\t25G83\n',
        "stderr": '',
    },
    'provenance-uname': {
        "argv": ['uname', '-a'],
        "exit": 0,
        "stdout": 'Darwin lvl04-dm354-a2824462-835b-4e34-bcd2-ab3e3d8206d2-12467FADAB66.local 25.6.0 Darwin Kernel Version 25.6.0: Fri Jul 31 19:16:43 PDT 2026; root:xnu-12377.161.14~5/RELEASE_ARM64_VMAPPLE arm64\n',
        "stderr": '',
    },
    'route-get-default': {
        "argv": ['route', '-n', 'get', 'default'],
        "exit": 0,
        "stdout": '   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.64.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n',
        "stderr": '',
    },
    'route-get-default-zh_CN': {
        "argv": ['route', '-n', 'get', 'default'],
        "exit": 0,
        "env": {'LANG': 'zh_CN.UTF-8', 'LC_ALL': 'zh_CN.UTF-8'},
        "stdout": '   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.64.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n',
        "stderr": '',
    },
    'route-get-default-ja_JP': {
        "argv": ['route', '-n', 'get', 'default'],
        "exit": 0,
        "env": {'LANG': 'ja_JP.UTF-8', 'LC_ALL': 'ja_JP.UTF-8'},
        "stdout": '   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.64.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n',
        "stderr": '',
    },
    'route-get-default-de_DE': {
        "argv": ['route', '-n', 'get', 'default'],
        "exit": 0,
        "env": {'LANG': 'de_DE.UTF-8', 'LC_ALL': 'de_DE.UTF-8'},
        "stdout": '   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.64.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n',
        "stderr": '',
    },
    'netstat-rn-inet-zh_CN': {
        "argv": ['netstat', '-rn', '-f', 'inet'],
        "exit": 0,
        "env": {'LANG': 'zh_CN.UTF-8', 'LC_ALL': 'zh_CN.UTF-8'},
        "stdout": 'Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.64.1       UGScg                 en0       \n127                127.0.0.1          UCS                   lo0       \n127.0.0.1          127.0.0.1          UH                    lo0       \n169.254            link#7             UCS                   en0      !\n192.168.64         link#7             UCS                   en0      !\n192.168.64.1/32    link#7             UCS                   en0      !\n192.168.64.1       5e:e9:1e:f:c3:64   UHLWIir               en0   1177\n192.168.64.3/32    link#7             UCS                   en0      !\n192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !\n224.0.0/4          link#7             UmCS                  en0      !\n224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       \n255.255.255.255/32 link#7             UCS                   en0      !\n',
        "stderr": '',
    },
    'route-get-8.8.8.8': {
        "argv": ['route', '-n', 'get', '8.8.8.8'],
        "exit": 0,
        "stdout": '   route to: 8.8.8.8\ndestination: default\n       mask: default\n    gateway: 192.168.64.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n',
        "stderr": '',
    },
    'route-get-127.0.0.1': {
        "argv": ['route', '-n', 'get', '127.0.0.1'],
        "exit": 0,
        "stdout": '   route to: 127.0.0.1\ndestination: 127.0.0.1\n  interface: lo0\n      flags: <UP,HOST,DONE,LOCAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n   49152     49152         0         0         0         0     16384         0 \n',
        "stderr": '',
    },
    'route-get-own-address': {
        "argv": ['route', '-n', 'get', '192.168.64.3'],
        "exit": 0,
        "stdout": '   route to: 192.168.64.3\ndestination: 192.168.64.3\n       mask: 255.255.255.255\n  interface: en0\n      flags: <UP,DONE,CLONING,STATIC>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500      -439 \n',
        "stderr": '',
    },
    'route-get-gateway-address': {
        "argv": ['route', '-n', 'get', '192.168.64.1'],
        "exit": 0,
        "stdout": '   route to: 192.168.64.1\ndestination: 192.168.64.1\n  interface: en0\n      flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF,ROUTER>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500      1098 \n',
        "stderr": '',
    },
    'route-get-broadcast': {
        "argv": ['route', '-n', 'get', '192.168.64.255'],
        "exit": 0,
        "stdout": '   route to: 192.168.64.255\ndestination: 192.168.64.255\n  interface: en0\n      flags: <UP,HOST,DONE,LLINFO,WASCLONED,BROADCAST,IFSCOPE>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500       -67 \n',
        "stderr": '',
    },
    'route-get-multicast': {
        "argv": ['route', '-n', 'get', '224.0.0.251'],
        "exit": 0,
        "stdout": '   route to: 224.0.0.251\ndestination: 224.0.0.251\n  interface: en0\n      flags: <UP,HOST,DONE,LLINFO,WASCLONED,MULTICAST,IFSCOPE>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n',
        "stderr": '',
    },
    'route-get-198.51.100.129-after': {
        "argv": ['route', '-n', 'get', '198.51.100.129'],
        "exit": 0,
        "stdout": '   route to: 198.51.100.129\ndestination: 198.51.100.128\n       mask: 255.255.255.128\n  interface: lo0\n      flags: <UP,DONE,STATIC,PRCLONING>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n   49152     49152         0         0         0         0     16384         0 \n',
        "stderr": '',
    },
    'route-get-through-tun': {
        "argv": ['route', '-n', 'get', '203.0.113.1'],
        "exit": 0,
        "stdout": '   route to: 203.0.113.1\ndestination: 128.0.0.0\n       mask: 128.0.0.0\n    gateway: 192.168.64.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n',
        "stderr": '',
    },
    'route-get-malformed': {
        "argv": ['route', '-n', 'get', '203.0.113.256'],
        "exit": 68,
        "stdout": '',
        "stderr": 'route: bad address: 203.0.113.256\n',
    },
    'route-get-missing-interface': {
        "argv": ['route', '-n', 'get', '-ifscope', 'utun99', '8.8.8.8'],
        "exit": 1,
        "stdout": '',
        "stderr": 'route: bad interface name\n',
    },
    'route-get-through-utun': {
        "argv": ['route', '-n', 'get', '203.0.113.1'],
        "exit": 0,
        "stdout": '   route to: 203.0.113.1\ndestination: 203.0.113.0\n       mask: 255.255.255.0\n  interface: utun3\n      flags: <UP,DONE,STATIC,PRCLONING>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1000         0 \n',
        "stderr": '',
    },
    'route-get-with-duplicates': {
        "argv": ['route', '-n', 'get', '203.0.113.1'],
        "exit": 0,
        "stdout": '   route to: 203.0.113.1\ndestination: 203.0.113.0\n       mask: 255.255.255.0\n    gateway: 192.168.64.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,IFSCOPE>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n',
        "stderr": '',
    },
    'netstat-rn-inet-before': {
        "argv": ['netstat', '-rn', '-f', 'inet'],
        "exit": 0,
        "stdout": 'Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.64.1       UGScg                 en0       \n127                127.0.0.1          UCS                   lo0       \n127.0.0.1          127.0.0.1          UH                    lo0       \n169.254            link#7             UCS                   en0      !\n192.168.64         link#7             UCS                   en0      !\n192.168.64.1/32    link#7             UCS                   en0      !\n192.168.64.1       5e:e9:1e:f:c3:64   UHLWIir               en0   1177\n192.168.64.3/32    link#7             UCS                   en0      !\n192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !\n224.0.0/4          link#7             UmCS                  en0      !\n224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       \n255.255.255.255/32 link#7             UCS                   en0      !\n',
        "stderr": '',
    },
    'netstat-rn-inet-after': {
        "argv": ['netstat', '-rn', '-f', 'inet'],
        "exit": 0,
        "stdout": 'Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.64.1       UGScg                 en0       \n100.64/10          192.168.64.1       UGSc                  en0       \n127                127.0.0.1          UCS                   lo0       \n127.0.0.1          127.0.0.1          UH                    lo0       \n169.254            link#7             UCS                   en0      !\n192.0.2.1          192.168.64.1       UGHS                  en0       \n192.0.2.2/32       192.168.64.1       UGSc                  en0       \n192.0.2.128/25     192.168.64.1       UGSc                  en0       \n192.168.64         link#7             UCS                   en0      !\n192.168.64.1/32    link#7             UCS                   en0      !\n192.168.64.1       5e:e9:1e:f:c3:64   UHLWIir               en0   1177\n192.168.64.3/32    link#7             UCS                   en0      !\n192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !\n198.18.0/15        192.168.64.1       UGSc                  en0       \n198.51.100/26      192.168.64.1       UGSc                  en0       \n198.51.100.128/25  lo0                USc                   lo0       \n203.0.113          192.168.64.1       UGSc                  en0       \n224.0.0/4          link#7             UmCS                  en0      !\n224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       \n255.255.255.255/32 link#7             UCS                   en0      !\n',
        "stderr": '',
    },
    'netstat-rn-after': {
        "argv": ['netstat', '-rn'],
        "exit": 0,
        "stdout": 'Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.64.1       UGScg                 en0       \n100.64/10          192.168.64.1       UGSc                  en0       \n127                127.0.0.1          UCS                   lo0       \n127.0.0.1          127.0.0.1          UH                    lo0       \n169.254            link#7             UCS                   en0      !\n192.0.2.1          192.168.64.1       UGHS                  en0       \n192.0.2.2/32       192.168.64.1       UGSc                  en0       \n192.0.2.128/25     192.168.64.1       UGSc                  en0       \n192.168.64         link#7             UCS                   en0      !\n192.168.64.1/32    link#7             UCS                   en0      !\n192.168.64.1       5e:e9:1e:f:c3:64   UHLWIir               en0   1177\n192.168.64.3/32    link#7             UCS                   en0      !\n192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !\n198.18.0/15        192.168.64.1       UGSc                  en0       \n198.51.100/26      192.168.64.1       UGSc                  en0       \n198.51.100.128/25  lo0                USc                   lo0       \n203.0.113          192.168.64.1       UGSc                  en0       \n224.0.0/4          link#7             UmCS                  en0      !\n224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       \n255.255.255.255/32 link#7             UCS                   en0      !\n\nInternet6:\nDestination                             Gateway                                 Flags               Netif Expire\ndefault                                 fe80::%utun0                            UGcIg               utun0       \ndefault                                 fe80::%utun1                            UGcIg               utun1       \ndefault                                 fe80::%utun2                            UGcIg               utun2       \ndefault                                 fe80::%utun3                            UGcIg               utun3       \n::1                                     ::1                                     UHL                   lo0       \nfe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0       \nfe80::1%lo0                             link#1                                  UHLI                  lo0       \nfe80::%en0/64                           link#7                                  UCI                   en0       \nfe80::144f:37fc:b6d5:4439%en0           12:46:7f:ad:ab:66                       UHLI                  lo0       \nfe80::%utun0/64                         fe80::458a:3158:7fbc:9a9b%utun0         UcI                 utun0       \nfe80::458a:3158:7fbc:9a9b%utun0         link#8                                  UHLI                  lo0       \nfe80::%utun1/64                         fe80::f992:c1c4:8854:ba08%utun1         UcI                 utun1       \nfe80::f992:c1c4:8854:ba08%utun1         link#9                                  UHLI                  lo0       \nfe80::%utun2/64                         fe80::ce81:b1c:bd2c:69e%utun2           UcI                 utun2       \nfe80::ce81:b1c:bd2c:69e%utun2           link#10                                 UHLI                  lo0       \nfe80::%utun3/64                         fe80::151a:ecca:cade:2eff%utun3         UcI                 utun3       \nfe80::151a:ecca:cade:2eff%utun3         link#11                                 UHLI                  lo0       \nff00::/8                                ::1                                     UmCI                  lo0       \nff00::/8                                link#7                                  UmCI                  en0       \nff00::/8                                fe80::458a:3158:7fbc:9a9b%utun0         UmCI                utun0       \nff00::/8                                fe80::f992:c1c4:8854:ba08%utun1         UmCI                utun1       \nff00::/8                                fe80::ce81:b1c:bd2c:69e%utun2           UmCI                utun2       \nff00::/8                                fe80::151a:ecca:cade:2eff%utun3         UmCI                utun3       \nff01::%lo0/32                           ::1                                     UmCI                  lo0       \nff01::%en0/32                           link#7                                  UmCI                  en0       \nff01::%utun0/32                         fe80::458a:3158:7fbc:9a9b%utun0         UmCI                utun0       \nff01::%utun1/32                         fe80::f992:c1c4:8854:ba08%utun1         UmCI                utun1       \nff01::%utun2/32                         fe80::ce81:b1c:bd2c:69e%utun2           UmCI                utun2       \nff01::%utun3/32                         fe80::151a:ecca:cade:2eff%utun3         UmCI                utun3       \nff02::%lo0/32                           ::1                                     UmCI                  lo0       \nff02::%en0/32                           link#7                                  UmCI                  en0       \nff02::%utun0/32                         fe80::458a:3158:7fbc:9a9b%utun0         UmCI                utun0       \nff02::%utun1/32                         fe80::f992:c1c4:8854:ba08%utun1         UmCI                utun1       \nff02::%utun2/32                         fe80::ce81:b1c:bd2c:69e%utun2           UmCI                utun2       \nff02::%utun3/32                         fe80::151a:ecca:cade:2eff%utun3         UmCI                utun3       \n',
        "stderr": '',
    },
    'netstat-rn-inet-final': {
        "argv": ['netstat', '-rn', '-f', 'inet'],
        "exit": 0,
        "stdout": 'Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.64.1       UGScg                 en0       \n127                127.0.0.1          UCS                   lo0       \n127.0.0.1          127.0.0.1          UH                    lo0       \n128.0/1            192.168.64.1       UGSc                  en0       \n169.254            link#7             UCS                   en0      !\n192.168.64         link#7             UCS                   en0      !\n192.168.64.1/32    link#7             UCS                   en0      !\n192.168.64.1       5e:e9:1e:f:c3:64   UHLWIir               en0   1177\n192.168.64.3/32    link#7             UCS                   en0      !\n192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !\n224.0.0/4          link#7             UmCS                  en0      !\n224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       \n255.255.255.255/32 link#7             UCS                   en0      !\n',
        "stderr": '',
    },
    'netstat-with-duplicates': {
        "argv": ['netstat', '-rn', '-f', 'inet'],
        "exit": 0,
        "stdout": 'Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.64.1       UGScg                 en0       \n127                127.0.0.1          UCS                   lo0       \n127.0.0.1          127.0.0.1          UH                    lo0       \n128.0/1            192.168.64.1       UGSc                  en0       \n169.254            link#7             UCS                   en0      !\n192.168.64         link#7             UCS                   en0      !\n192.168.64.1/32    link#7             UCS                   en0      !\n192.168.64.1       a6:77:f3:60:e5:64  UHLWIir               en0   1190\n192.168.64.7/32    link#7             UCS                   en0      !\n192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !\n203.0.113          192.168.64.1       UGSc                  en0       \n203.0.113          lo0                UScI                  lo0       \n203.0.113          192.168.64.1       UGScI                 en0       \n224.0.0/4          link#7             UmCS                  en0      !\n224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       \n255.255.255.255/32 link#7             UCS                   en0      !\n',
        "stderr": '',
    },
    'netstat-after-one-delete': {
        "argv": ['netstat', '-rn', '-f', 'inet'],
        "exit": 0,
        "stdout": 'Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.64.1       UGScg                 en0       \n127                127.0.0.1          UCS                   lo0       \n127.0.0.1          127.0.0.1          UH                    lo0       \n128.0/1            192.168.64.1       UGSc                  en0       \n169.254            link#7             UCS                   en0      !\n192.168.64         link#7             UCS                   en0      !\n192.168.64.1/32    link#7             UCS                   en0      !\n192.168.64.1       a6:77:f3:60:e5:64  UHLWIir               en0   1189\n192.168.64.7/32    link#7             UCS                   en0      !\n192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !\n203.0.113          lo0                UScI                  lo0       \n203.0.113          192.168.64.1       UGScI                 en0       \n224.0.0/4          link#7             UmCS                  en0      !\n224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       \n255.255.255.255/32 link#7             UCS                   en0      !\n',
        "stderr": '',
    },
    'netstat-with-utun-route': {
        "argv": ['netstat', '-rn', '-f', 'inet'],
        "exit": 0,
        "stdout": 'Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.64.1       UGScg                 en0       \n10.255.0.2         10.255.0.1         UH                  utun3       \n127                127.0.0.1          UCS                   lo0       \n127.0.0.1          127.0.0.1          UH                    lo0       \n128.0/1            192.168.64.1       UGSc                  en0       \n169.254            link#7             UCS                   en0      !\n192.168.64         link#7             UCS                   en0      !\n192.168.64.1/32    link#7             UCS                   en0      !\n192.168.64.1       a6:77:f3:60:e5:64  UHLWIir               en0   1189\n192.168.64.7/32    link#7             UCS                   en0      !\n192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !\n203.0.113          utun3              USc                 utun3       \n224.0.0/4          link#7             UmCS                  en0      !\n224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0       \n255.255.255.255/32 link#7             UCS                   en0      !\n',
        "stderr": '',
    },
    'route-add-net-24': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '203.0.113.0/24', '192.168.64.1'],
        "exit": 0,
        "stdout": 'add net 203.0.113.0: gateway 192.168.64.1\n',
        "stderr": '',
    },
    'route-add-net-24-again': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '203.0.113.0/24', '192.168.64.1'],
        "exit": 0,
        "stdout": 'add net 203.0.113.0: gateway 192.168.64.1: File exists\n',
        "stderr": 'route: writing to routing socket: File exists\n',
    },
    'route-add-unprivileged': {
        "argv": ['route', '-n', 'add', '-net', '203.0.113.0/24', '192.168.64.1'],
        "exit": 77,
        "stdout": '',
        "stderr": 'route: must be root to alter routing table\n',
    },
    'route-add-tun': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '203.0.113.0/24', '-interface', 'utun0'],
        "exit": 0,
        "stdout": 'add net 203.0.113.0: gateway utun0: Network is unreachable\n',
        "stderr": 'route: writing to routing socket: Network is unreachable\n',
    },
    'route-add-bad-interface': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '203.0.113.0/24', '-interface', 'utun99'],
        "exit": 68,
        "stdout": '',
        "stderr": 'route: bad address: utun99\n',
    },
    'route-add-missing-interface-name': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '203.0.113.0/24', '-interface'],
        "exit": 0,
        "stdout": 'add net 203.0.113.0: Invalid argument\n',
        "stderr": 'route: writing to routing socket: Invalid argument\n',
    },
    'route-add-default-existing': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '0.0.0.0/0', '192.168.64.1'],
        "exit": 0,
        "stdout": 'add net 0.0.0.0: gateway 192.168.64.1: File exists\n',
        "stderr": 'route: writing to routing socket: File exists\n',
    },
    'route-add-interface-scoped': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '198.51.100.128/25', '-interface', 'lo0'],
        "exit": 0,
        "stdout": 'add net 198.51.100.128: gateway lo0\n',
        "stderr": '',
    },
    'route-add-malformed-prefix': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '203.0.113.0/33', '192.168.64.1'],
        "exit": 0,
        "stdout": 'add net 203.0.113.0: gateway 192.168.64.1\n',
        "stderr": '',
    },
    'add-through-utun': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '203.0.113.0/24', '-interface', 'utun3'],
        "exit": 0,
        "stdout": 'add net 203.0.113.0: gateway utun3\n',
        "stderr": '',
    },
    'add-scoped-en0': {
        "argv": ['sudo', '-n', 'route', '-n', 'add', '-net', '203.0.113.0/24', '-ifscope', 'en0', '192.168.64.1'],
        "exit": 0,
        "stdout": 'add net 203.0.113.0: gateway 192.168.64.1\n',
        "stderr": '',
    },
    'delete-through-utun': {
        "argv": ['sudo', '-n', 'route', '-n', 'delete', '-net', '203.0.113.0/24'],
        "exit": 0,
        "stdout": 'delete net 203.0.113.0\n',
        "stderr": '',
    },
    'delete-plain': {
        "argv": ['sudo', '-n', 'route', '-n', 'delete', '-net', '203.0.113.0/24'],
        "exit": 0,
        "stdout": 'delete net 203.0.113.0\n',
        "stderr": '',
    },
    'route-delete-net-24': {
        "argv": ['sudo', '-n', 'route', '-n', 'delete', '-net', '203.0.113.0/24'],
        "exit": 0,
        "stdout": 'delete net 203.0.113.0\n',
        "stderr": '',
    },
    'route-delete-net-24-again': {
        "argv": ['sudo', '-n', 'route', '-n', 'delete', '-net', '203.0.113.0/24'],
        "exit": 0,
        "stdout": 'delete net 203.0.113.0: not in table\n',
        "stderr": 'route: writing to routing socket: not in table\n',
    },
    'route-delete-interface-scoped': {
        "argv": ['sudo', '-n', 'route', '-n', 'delete', '-net', '198.51.100.128/25'],
        "exit": 0,
        "stdout": 'delete net 198.51.100.128\n',
        "stderr": '',
    },
    'ifconfig-utun3-before': {
        "argv": ['ifconfig', 'utun3'],
        "exit": 0,
        "stdout": 'utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1000\n\tinet6 fe80::ce81:b1c:bd2c:69e%utun3 prefixlen 64 scopeid 0xb \n\tnd6 options=201<PERFORMNUD,DAD>\n',
        "stderr": '',
    },
    'ifconfig-utun3-after': {
        "argv": ['ifconfig', 'utun3'],
        "exit": 0,
        "stdout": 'utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1000\n\tinet6 fe80::ce81:b1c:bd2c:69e%utun3 prefixlen 64 scopeid 0xb \n\tinet 10.255.0.1 --> 10.255.0.2 netmask 0xffffffff\n\tnd6 options=201<PERFORMNUD,DAD>\n',
        "stderr": '',
    },
    'timing-netstat-inet': {
        "argv": ['netstat', '-rn', '-f', 'inet'],
        "exit": 0,
        "elapsedMs": 25.12,
        "samplesMs": [15.86, 23.78, 24.63, 24.72, 25.09, 25.12, 25.24, 25.88, 25.89, 26.88],
        "stdout": '',
        "stderr": '',
    },
    'timing-route-get': {
        "argv": ['route', '-n', 'get', '8.8.8.8'],
        "exit": 0,
        "elapsedMs": 26.29,
        "samplesMs": [14.7, 24.69, 24.72, 26.02, 26.23, 26.29, 28.01, 28.74, 30.0, 30.49],
        "stdout": '',
        "stderr": '',
    },
    'timing-true': {
        "argv": ['/usr/bin/true'],
        "exit": 0,
        "elapsedMs": 3.15,
        "samplesMs": [2.24, 2.28, 2.41, 2.43, 2.92, 3.15, 3.6, 3.69, 5.24, 7.07],
        "stdout": '',
        "stderr": '',
    },
}

# ---------------------------------------------------------------------------------------------
# Reference implementations. Every expectation in the vector is computed by these.
# ---------------------------------------------------------------------------------------------

# The netstat flag for an entry the kernel generated rather than one anybody configured.
#
# Excluded from the conflict answer. BSD keeps address resolution in the routing table, so a host
# that has been talked to recently has a /32 entry of its own -- the gateway, the subnet broadcast
# address and every multicast group that has been joined all appear. Counting those as conflicts
# would refuse the bypass routes, which are /32s for the control endpoint, STUN, TURN and the peer
# addresses, exactly the addresses most likely to have been talked to already. And a refused bypass
# route is the leak this feature exists to prevent: the transport would fall under whichever rule
# covers it and be sent into the tunnel it carries.
KERNEL_GENERATED_FLAG = "W"

# What a failed routing command is called. Same two names as the Windows side, so the installer
# reads the same on both.
FAILURE_DENIED = "permission-denied"
FAILURE_OTHER = "failed"

# The two failures that are not failures.
#
# "not in table" is a removal of something already gone, which is the outcome the caller asked for.
# It matters more than it looks: the journal is walked at startup, and on a machine that has
# rebooted none of the routes in it are there any more, so every entry reports this.
NOT_IN_TABLE = "not in table"
# "must be root" is the one worth naming, because the fix is to run elevated and no retry gets
# there.
MUST_BE_ROOT = "must be root"


def decimal_value(digits, limit):
    """The value of a run of decimal digits, or None if it is not one or is out of range.

    A leading zero is refused rather than skipped. `route` parses addresses with inet_aton, which
    reads a leading zero as octal: to it, 010.0.0.1 is 8.0.0.1. Reading the same text as decimal
    here would mean the conflict check asking about one prefix while the install created another,
    and the way to not have two readings of one string is to accept only the spelling that has
    one.
    """
    if not digits or not digits.isdigit():
        return None
    if len(digits) > 1 and digits[0] == "0":
        return None
    value = int(digits)
    return value if value <= limit else None


def parse_route_get(stdout, stderr=""):
    """Reference reading of `route -n get <address>`.

    Returns {"gateway": str, "interface": str} or None.

    The gateway is empty for a destination that is on-link, where `route` prints no gateway line at
    all. Sampled rather than assumed: asked about the gateway's own address -- which has a
    WASCLONED link-level entry carrying a MAC address -- it still prints no gateway line, so the
    field never holds something that is not an address.
    """
    if stderr.strip():
        return None
    gateway = ""
    interface = ""
    for line in stdout.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if key == "gateway":
            gateway = value
        elif key == "interface":
            interface = value
    if not interface:
        return None
    if gateway and not valid_address(gateway):
        # Not an address, so it cannot be a next hop. The only thing done with this value is to
        # put it back on a `route add` command line, where a non-address is either another
        # argument or an error. Treating it as on-link asks for a route out of the interface,
        # which is what an entry without a usable gateway means anyway.
        gateway = ""
    return {"gateway": gateway, "interface": interface}


def normalise_prefix(text):
    """netstat's destination column, or a rule's CIDR, as one canonical 'a.b.c.d/len'.

    Returns "" for anything that is not IPv4, which is how the IPv6 half of the table is left
    alone.

    netstat abbreviates. The sampled table renders 0.0.0.0/0 as "default", 127.0.0.0/8 as "127",
    169.254.0.0/16 as "169.254", 203.0.113.0/24 as "203.0.113", 100.64.0.0/10 as "100.64/10",
    198.51.100.0/26 as "198.51.100/26" and a host route as a bare address. None of that is
    guessable, which is why it is sampled; the rule for reading it back is that a destination with
    no length carries one octet per eight bits, and a destination with a length means what it says
    once the missing trailing octets are filled in with zeroes.

    The address is then masked by the length. Two spellings of one prefix have to compare equal or
    the conflict check is answering a different question than it was asked.
    """
    value = (text or "").strip()
    if not value:
        return ""
    if value == "default":
        return "0.0.0.0/0"
    address, slash, length = value.partition("/")
    octets = address.split(".")
    if not 1 <= len(octets) <= 4:
        return ""
    numbers = []
    for octet in octets:
        number = decimal_value(octet, 255)
        if number is None:
            return ""
        numbers.append(number)
    if slash:
        bits = decimal_value(length, 32)
        if bits is None:
            return ""
    else:
        bits = 8 * len(numbers)
    numbers += [0] * (4 - len(numbers))
    packed = (numbers[0] << 24) | (numbers[1] << 16) | (numbers[2] << 8) | numbers[3]
    mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    packed &= mask
    return "%d.%d.%d.%d/%d" % ((packed >> 24) & 0xFF, (packed >> 16) & 0xFF,
                               (packed >> 8) & 0xFF, packed & 0xFF, bits)


def parse_netstat_table(stdout):
    """Reference reading of `netstat -rn`. Returns the IPv4 rows.

    Only the rows under the "Internet:" heading. The gate is load-bearing rather than tidy:
    "Internet6:" has a "default" row of its own -- four of them on the sampling machine, one per
    utun -- and "default" is the one destination whose IPv6 spelling is indistinguishable from its
    IPv4 spelling. Without the gate, asking whether anything owns 0.0.0.0/0 on a machine with IPv6
    would find phantom routes.

    Rows carry four or five columns: the fifth is Expire, which holds a number, or "!", or nothing
    at all. It is not read, and the parser must not require it.
    """
    rows = []
    inside = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":"):
            inside = stripped == "Internet:"
            continue
        if not inside or stripped.startswith("Destination"):
            continue
        fields = stripped.split()
        if len(fields) < 4:
            continue
        prefix = normalise_prefix(fields[0])
        if not prefix:
            continue
        rows.append({"prefix": prefix, "destination": fields[0], "gateway": fields[1],
                     "flags": fields[2], "netif": fields[3]})
    return rows


def describe_route(row):
    """One line an operator can match against their own `netstat -rn` output.

    The columns are restated in netstat's own words, including calling the second one a gateway
    when it holds an interface name: that is what the table says, and an operator comparing this
    line against the table should not have to reconcile two vocabularies.
    """
    return "%s gateway %s netif %s flags %s" % (row["prefix"], row["gateway"], row["netif"],
                                                row["flags"])


def describe_routes(rows):
    """Turns the routes on one prefix into (present, description)."""
    if not rows:
        return False, ""
    description = describe_route(rows[0])
    if len(rows) > 1:
        # The count matters to whoever has to clear the prefix: one removal will not be enough,
        # and retrying is a worse way to find that out.
        description += " (+%d more)" % (len(rows) - 1)
    return True, description


def conflict_from_table(stdout, prefix):
    """Does anything already own this exact prefix.

    Exact prefix, not a longest-prefix lookup, for the same reason as on Windows: the question is
    ownership of this prefix, not reachability of an address, and under a default route everything
    is reachable. `route -n get` cannot answer it at all -- asked about an unrouted address it
    returns the default route -- which is why the whole table is read instead.
    """
    wanted = normalise_prefix(prefix)
    if not wanted:
        return False, ""
    matching = [row for row in parse_netstat_table(stdout)
                if row["prefix"] == wanted and KERNEL_GENERATED_FLAG not in row["flags"]]
    return describe_routes(matching)


def classify_failure(stdout, stderr):
    """Did a `route add` or `route delete` work, and if not, how did it fail.

    Returns "", FAILURE_DENIED or FAILURE_OTHER.

    The exit status is not consulted, because it is 0 for "File exists", for "not in table", for
    "Network is unreachable" and for "Invalid argument" -- every failure sampled here except a
    malformed address returns success. What does separate them is stderr, which is empty for every
    successful mutation sampled and carries "route: writing to routing socket: <error>" for every
    failed one.

    Keyed on stderr being non-empty rather than on a list of error texts. The errors are strerror
    of whatever the routing socket returned, so the list has no end; and an unrecognised error
    would otherwise read as success, which is the direction that leaves a rule believed installed
    while its traffic goes out of the physical interface. Noise on stderr fails the other way: the
    install is reported failed, the installer withdraws a route it did install, and nothing leaks.
    """
    combined = (stdout or "") + "\n" + (stderr or "")
    if MUST_BE_ROOT in combined:
        return FAILURE_DENIED
    if NOT_IN_TABLE in combined:
        # The route is not in the table, which is what the caller asked for.
        return ""
    if (stderr or "").strip():
        return FAILURE_OTHER
    return ""


# ---------------------------------------------------------------------------------------------
# Arguments. No shell anywhere -- these are argv arrays handed to exec -- so nothing here is
# quoted or escaped, and that is the whole point: on Windows the same commands go through
# PowerShell and a prefix carrying a quote becomes a second command, while here a prefix carrying
# a quote is simply a prefix `route` will reject. What is left to defend against is a value that
# reads as a flag, and a value that reads as a valid prefix but is not one.
# ---------------------------------------------------------------------------------------------

def valid_address(value):
    """An IPv4 address, exactly four octets, nothing else."""
    text = value or ""
    if text != text.strip() or not text:
        return False
    octets = text.split(".")
    if len(octets) != 4:
        return False
    return all(decimal_value(octet, 255) is not None for octet in octets)


def valid_prefix(value):
    """An IPv4 prefix in full: four octets and a length.

    The length is required, and 33 is refused. Both matter because `route` does neither: asked to
    add 203.0.113.0/33 it prints a success line naming 203.0.113.0 and installs 128.0/1.
    """
    text = value or ""
    address, slash, length = text.partition("/")
    if not slash or not valid_address(address):
        return False
    return decimal_value(length, 32) is not None


def valid_interface_name(value):
    """An interface name that cannot be read as anything else.

    Must start with a letter, so it can never be taken for a flag, and must stay inside the
    letters, digits, underscore and dot that real names use -- en0, utun3, bridge0, vlan1. The
    length limit is the kernel's: IFNAMSIZ is 16 including the terminator.

    Whitelisted rather than escaped, which is the opposite of the Windows treatment of the same
    value. There the adapter name reaches PowerShell as part of a script and has to be escaped
    because operators legitimately use spaces and non-ASCII in it; here it is one element of an
    argv array, so there is nothing to escape, and the only thing that can go wrong is `route`
    reading the name as an address -- which it does: given an interface that does not exist it
    reports "route: bad address: utun99".
    """
    text = value or ""
    if not 1 <= len(text) <= 15:
        return False
    if not (text[0].isascii() and text[0].isalpha()):
        return False
    for character in text:
        if not (character.isascii() and (character.isalnum() or character in "_.")):
            return False
    return True


def show_table_args():
    """Read the whole table. IPv4 only: the IPv6 section is a different column layout and this
    feature does not route IPv6 yet."""
    return ["netstat", "-rn", "-f", "inet"]


def find_route_args(address):
    """Where an address would go right now, used to resolve bypass next hops.

    `-n` so no name lookup is attempted. It makes no difference to the output -- sampled with and
    without -- but a resolver that does not answer would hold the process for as long as the
    resolver takes, and this runs while the tunnel is being brought up.
    """
    if not valid_address(address):
        raise ValueError("refusing to build a route command from this argument: %r" % (address,))
    return ["route", "-n", "get", address]


def install_interface_args(prefix, name):
    """Send a prefix out of an interface, which is how the rules' routes reach the TUN."""
    if not valid_prefix(prefix):
        raise ValueError("refusing to build a route command from this argument: %r" % (prefix,))
    if not valid_interface_name(name):
        raise ValueError("refusing to build a route command from this argument: %r" % (name,))
    return ["route", "-n", "add", "-net", prefix, "-interface", name]


def install_gateway_args(prefix, gateway):
    """Send a prefix to a next hop, which is how a bypass keeps the transport off the tunnel."""
    if not valid_prefix(prefix):
        raise ValueError("refusing to build a route command from this argument: %r" % (prefix,))
    if not valid_address(gateway):
        raise ValueError("refusing to build a route command from this argument: %r" % (gateway,))
    return ["route", "-n", "add", "-net", prefix, gateway]


def remove_args(prefix):
    """Withdraw a prefix. `-net` for every prefix including a /32, which is sampled as working:
    one form means the withdrawal cannot disagree with the install about what was installed."""
    if not valid_prefix(prefix):
        raise ValueError("refusing to build a route command from this argument: %r" % (prefix,))
    return ["route", "-n", "delete", "-net", prefix]


# ---------------------------------------------------------------------------------------------
# Cases.
# ---------------------------------------------------------------------------------------------

def sampled_case(name, note, key=None):
    """A case whose input is one of the capture records above."""
    record = SAMPLED[key or name]
    return {
        "name": name,
        "note": note,
        "command": " ".join(record["argv"]),
        "stdout": record["stdout"],
        "stderr": record["stderr"],
        "exit": record["exit"],
        "sampled": True,
    }


ROUTE_GET = []
for _name, _key, _note in [
    ("default", "route-get-default", "默认路由，有网关"),
    ("remote-address", "route-get-8.8.8.8", "任意远端地址，落到默认路由上"),
    ("loopback", "route-get-127.0.0.1", "环回，主机路由，没有网关行"),
    ("own-address", "route-get-own-address", "本机自己的地址，直连"),
    ("gateway-address", "route-get-gateway-address",
     "网关自己的地址。它在路由表里有一条带 MAC 的链路层条目，但 route get 仍然不打印 gateway 行——"
     "这一条是采样出来的，不是假设出来的"),
    ("broadcast", "route-get-broadcast", "子网广播地址，同样没有网关"),
    ("multicast", "route-get-multicast", "组播地址"),
    ("interface-route", "route-get-198.51.100.129-after",
     "一条指向接口而不是网关的路由，命中它的地址没有网关行"),
    ("half-the-internet", "route-get-through-tun",
     "203.0.113.1 落在 128.0.0.0/1 上——那是 /33 那次安装留下的残留，见 malformedPrefix"),
    ("through-the-tunnel", "route-get-through-utun",
     "命中一条指向 utun 的路由。没有网关行，interface 就是 TUN 本身——旁路解析靠这个判断"
     "「这个地址已经被隧道盖住了」"),
    ("scoped-duplicates", "route-get-with-duplicates",
     "同一前缀上有三条路由时，route get 只回答其中一条。这正是冲突检查不能用 route get 的理由。"),
    ("bad-address", "route-get-malformed", "地址不合法，报在 stderr 上，退出码 68"),
    ("bad-interface", "route-get-missing-interface", "接口不存在，报的是 bad interface name"),
]:
    _case = sampled_case(_name, _note, _key)
    _parsed = parse_route_get(_case["stdout"], _case["stderr"])
    _case["expect"] = {"parsed": _parsed is not None}
    if _parsed:
        _case["expect"]["gateway"] = _parsed["gateway"]
        _case["expect"]["interface"] = _parsed["interface"]
    ROUTE_GET.append(_case)

# One constructed case, labelled as such: a gateway field holding something that is not an address.
# Not sampled, because no sampled output has one -- which is the finding. It is here because the
# value's only use is to be put back on a `route add` command line, and the implementations have to
# agree on what happens if it ever is not an address.
_CONSTRUCTED_GET = ("   route to: 203.0.113.1\ndestination: 203.0.113.0\n       mask: "
                    "255.255.255.0\n    gateway: link#7\n  interface: en0\n")
_parsed = parse_route_get(_CONSTRUCTED_GET)
ROUTE_GET.append({
    "name": "gateway-that-is-not-an-address",
    "note": "构造，不是采样。没有任何采样输出长这样，这正是那个发现；放在这里是因为这个值唯一的用途"
            "就是被拼回 route add 的命令行，三端必须对「万一它不是地址」给出同一个答案。",
    "command": "route -n get 203.0.113.1",
    "stdout": _CONSTRUCTED_GET,
    "stderr": "",
    "exit": 0,
    "expect": {"parsed": True, "gateway": _parsed["gateway"], "interface": _parsed["interface"]},
    "sampled": False,
})

# Every destination spelling that appears in the sampled tables, plus what has to be rejected.
_DESTINATIONS = []
for _table_key in ("netstat-rn-inet-after", "netstat-rn-after", "netstat-rn-inet-final",
                   "netstat-with-duplicates", "netstat-with-utun-route"):
    for _line in SAMPLED[_table_key]["stdout"].splitlines():
        _stripped = _line.strip()
        if not _stripped or _stripped.endswith(":") or _stripped.startswith("Destination"):
            continue
        _first = _stripped.split()[0]
        if _first not in _DESTINATIONS:
            _DESTINATIONS.append(_first)
for _extra in ["10.0.0.0/8", "10.1.2.3/8", "198.51.100.200/26", "0.0.0.0/0", "255.255.255.255/32",
               "010.0.0.1/8", "10.0.0.0/08", "0.0.0.0/00",
               "link#7", "5e:e9:1e:f:c3:64", "", "   ", "1.2.3.4.5", "1.2.3.256", "1.2.3.4/33",
               "1.2.3.4/012", "abc", "10./8", "-net"]:
    if _extra not in _DESTINATIONS:
        _DESTINATIONS.append(_extra)

NORMALISE = [{"input": _text, "expect": normalise_prefix(_text)} for _text in _DESTINATIONS]

TABLE = sampled_case("table", "整张 IPv4 路由表，安装了七条测试路由之后抓的",
                     "netstat-rn-inet-after")
TABLE["expect"] = {
    "rows": len(parse_netstat_table(TABLE["stdout"])),
    "prefixes": [row["prefix"] for row in parse_netstat_table(TABLE["stdout"])],
}

BOTH_FAMILIES = sampled_case(
    "both-families",
    "netstat -rn 不带 -f inet 的输出。Internet6: 段里有四条 default，每个 utun 一条——"
    "「default」是唯一一个 IPv6 写法和 IPv4 写法长得一样的目的地，所以按段落切分是必需的，不是整洁。",
    "netstat-rn-after")
BOTH_FAMILIES["expect"] = {
    "rows": len(parse_netstat_table(BOTH_FAMILIES["stdout"])),
    "prefixes": [row["prefix"] for row in parse_netstat_table(BOTH_FAMILIES["stdout"])],
}

DUPLICATES = sampled_case(
    "duplicates",
    "同一条前缀上的三条路由：一条未限定作用域的，两条 -ifscope 限定的。macOS 上第二次普通 add 会报 "
    "File exists，但限定作用域的可以并存——所以「+N more」这个计数是真的会发生的，不是摆设。"
    "另外：不带 -ifscope 的 delete 只删掉未限定的那一条，限定的两条还在表里。",
    "netstat-with-duplicates")
DUPLICATES["expect"] = {
    "rows": len(parse_netstat_table(DUPLICATES["stdout"])),
    "prefixes": [row["prefix"] for row in parse_netstat_table(DUPLICATES["stdout"])],
}

TUN_ROUTE = sampled_case(
    "tun-route",
    "一条真的指向 utun3 的路由，Gateway 列和 Netif 列都是接口名，flags 是 USc（没有 G）。"
    "这是本功能实际会装的那一条。",
    "netstat-with-utun-route")
TUN_ROUTE["expect"] = {
    "rows": len(parse_netstat_table(TUN_ROUTE["stdout"])),
    "prefixes": [row["prefix"] for row in parse_netstat_table(TUN_ROUTE["stdout"])],
}

CONFLICT = []
for _prefix, _note, _table_key in [
    ("0.0.0.0/0", "默认路由。全隧道规则要的就是这条前缀，任何能上网的机器上都已经有人占着。",
     "netstat-rn-inet-after"),
    ("203.0.113.0/24", "表里写成「203.0.113」，没有长度", "netstat-rn-inet-after"),
    ("100.64.0.0/10", "表里写成「100.64/10」", "netstat-rn-inet-after"),
    ("198.51.100.0/26", "表里写成「198.51.100/26」：三个八位组加一个 /26", "netstat-rn-inet-after"),
    ("198.51.100.128/25", "指向接口的那条，Gateway 列里是接口名 lo0", "netstat-rn-inet-after"),
    ("198.51.100.0/24", "表里有 /26 和 /25，没有 /24。精确比较，所以不冲突。",
     "netstat-rn-inet-after"),
    ("0.0.0.0/1", "默认路由覆盖得到它，但没人占着这条前缀本身。最长前缀查找会答错的那一条。",
     "netstat-rn-inet-after"),
    ("192.0.2.1/32", "-host 装出来的，表里写成裸地址", "netstat-rn-inet-after"),
    ("192.168.64.1/32",
     "两行都归一到这条前缀：一行是 /32 接口路由，一行是带 MAC 的 ARP 条目（flags 里有 W）。"
     "内核生成的那行被排除，所以描述里不带「+1 more」——这一条是 W 过滤的载荷。",
     "netstat-rn-inet-after"),
    ("192.168.64.255/32",
     "只有广播那一行，flags UHLWbI。过滤掉之后是「不冲突」——这一条 W 过滤改变的是有无，不是条数。",
     "netstat-rn-inet-after"),
    ("224.0.0.251/32", "只有组播那一行，同样是内核生成的", "netstat-rn-inet-after"),
    ("128.0.0.0/1", "/33 那次安装留下的残留，在最终表里", "netstat-rn-inet-final"),
    ("10.0.0.0/8", "谁都没占", "netstat-rn-inet-after"),
    ("", "空前缀，归一不出来，不冲突", "netstat-rn-inet-after"),
    ("203.0.113.0/33", "不合法的前缀，归一不出来", "netstat-rn-inet-after"),
]:
    _present, _description = conflict_from_table(SAMPLED[_table_key]["stdout"], _prefix)
    CONFLICT.append({
        "prefix": _prefix,
        "note": _note,
        "table": _table_key,
        "expect": {"present": _present, "existing": _description},
    })

for _prefix, _note, _table_key in [
    ("203.0.113.0/24",
     "三条路由共用这条前缀，描述里带「+2 more」。清掉这条前缀不是删一次就够——"
     "而靠重试去发现这件事是更差的方式。",
     "netstat-with-duplicates"),
    ("203.0.113.0/24",
     "只剩两条限定作用域的。不带 -ifscope 的 delete 只删掉了未限定的那一条。",
     "netstat-after-one-delete"),
    ("203.0.113.0/24", "指向 utun3 的那一条", "netstat-with-utun-route"),
]:
    _present, _description = conflict_from_table(SAMPLED[_table_key]["stdout"], _prefix)
    CONFLICT.append({
        "prefix": _prefix,
        "note": _note,
        "table": _table_key,
        "expect": {"present": _present, "existing": _description},
    })

# The same question against the two-family table, which is where the section gate earns its place.
for _prefix, _note in [
    ("0.0.0.0/0", "两个地址族的表。IPv4 那条 default 要找到，Internet6: 段里那四条 default 不能算，"
                  "所以描述里不会出现「+4 more」。"),
    ("203.0.113.0/24", "IPv4 段里的那条，不受 IPv6 段影响"),
]:
    _present, _description = conflict_from_table(SAMPLED["netstat-rn-after"]["stdout"], _prefix)
    CONFLICT.append({
        "prefix": _prefix,
        "note": _note,
        "table": "netstat-rn-after",
        "expect": {"present": _present, "existing": _description},
    })

COMMAND_RESULTS = []
for _name, _key, _note in [
    ("add-succeeded", "route-add-net-24", "成功。stdout 有一行，stderr 空的。"),
    ("add-already-exists", "route-add-net-24-again",
     "同一条前缀装第二次。退出码 0，stdout 那行末尾多了「: File exists」，stderr 上有 socket 错误。"
     "信退出码的实现会把这次失败当成成功。"),
    ("add-not-root", "route-add-unprivileged",
     "非 root。stdout 是空的——只看 stdout 的分类器会把这次最重要的失败当成成功。"),
    ("add-interface-has-no-address", "route-add-tun",
     "把路由指向一个没有 IPv4 地址的 utun。退出码 0，错误是 Network is unreachable。"
     "这意味着 macOS 上 TUN 必须先配好 IPv4 地址，路由才能指过去。"),
    ("add-bad-interface-name", "route-add-bad-interface",
     "接口不存在时，route 把接口名当地址报错：bad address: utun99。退出码 68。"),
    ("add-missing-interface-value", "route-add-missing-interface-name",
     "-interface 后面什么都没跟，报 Invalid argument，退出码仍然是 0"),
    ("add-default-already-exists", "route-add-default-existing",
     "0.0.0.0/0 已经有人占着。全隧道规则在每台能上网的机器上都会走到这一条。"),
    ("add-interface-scoped-succeeded", "route-add-interface-scoped",
     "指向接口的安装成功了。stdout 里 gateway 后面跟的是接口名。"),
    ("add-malformed-prefix-succeeded", "route-add-malformed-prefix",
     "/33 被接受了。打印的是成功行，退出码 0，装进去的是 128.0/1——输出里看不出来，只有表里看得出来。"
     "见 malformedPrefix。"),
    ("add-through-tun-succeeded", "add-through-utun",
     "指向 utun 的安装成功了——在给那个 utun 配上 IPv4 地址之后。"
     "同一条命令在没有地址的 utun 上报 Network is unreachable，见上一条。"),
    ("add-scoped-alongside-existing", "add-scoped-en0",
     "同一前缀上已经有一条未限定作用域的路由时，-ifscope 的 add 成功了"),
    ("delete-through-tun", "delete-through-utun", "撤销指向 utun 的那一条"),
    ("delete-succeeded", "route-delete-net-24", "撤销成功"),
    ("delete-not-in-table", "route-delete-net-24-again",
     "撤销一条已经不在表里的前缀。算成功：调用方要的结果已经成立。"
     "开机后第一次清理会把日志里每一条都走到这里，因为这些路由都不跨重启存在。"),
    ("delete-interface-scoped", "route-delete-interface-scoped", "撤销指向接口的那条"),
]:
    _case = sampled_case(_name, _note, _key)
    _case["expect"] = {"failure": classify_failure(_case["stdout"], _case["stderr"])}
    COMMAND_RESULTS.append(_case)

COMMANDS = {
    "showTable": show_table_args(),
    "findRoute": [
        {"address": "8.8.8.8", "argv": find_route_args("8.8.8.8")},
        {"address": "192.168.1.1", "argv": find_route_args("192.168.1.1")},
    ],
    "installInterface": [
        {"prefix": "203.0.113.0/24", "interface": "utun3",
         "argv": install_interface_args("203.0.113.0/24", "utun3")},
        {"prefix": "0.0.0.0/0", "interface": "utun3",
         "argv": install_interface_args("0.0.0.0/0", "utun3")},
        {"prefix": "10.0.0.0/8", "interface": "en0",
         "argv": install_interface_args("10.0.0.0/8", "en0")},
    ],
    "installGateway": [
        {"prefix": "198.51.100.7/32", "gateway": "192.168.1.1",
         "argv": install_gateway_args("198.51.100.7/32", "192.168.1.1")},
    ],
    "remove": [
        {"prefix": "203.0.113.0/24", "argv": remove_args("203.0.113.0/24")},
        {"prefix": "198.51.100.7/32", "argv": remove_args("198.51.100.7/32")},
    ],
}

REJECTED_ARGUMENTS = []
for _kind, _value, _note in [
    ("prefix", "203.0.113.0/33",
     "route 会接受它，打印成功行，然后装上 128.0/1。Windows 上 New-NetRoute 会拒绝同样的参数，"
     "所以那边的前置校验是多一层防线；这边它是唯一的防线。"),
    ("prefix", "203.0.113.0", "没有长度。route 会当成一条主机路由或者按类推断，我们不猜。"),
    ("prefix", "203.0.113.256/24", "八位组越界"),
    ("prefix", "-net", "会被 route 当成一个选项"),
    ("prefix", "--", "同上"),
    ("prefix", "203.0.113.0/24 -interface lo0",
     "argv 里没有 shell，所以这不是注入，只是一个 route 读不懂的前缀。拒了它是因为"
     "「读不懂」和「读懂成别的东西」在这里只差一个空格。"),
    ("prefix", "203.0.113.0/024", "前导零，不接受"),
    ("prefix", "010.0.113.0/24",
     "前导零。route 用 inet_aton 解析地址，前导零按八进制读——010.0.113.0 对它是 8.0.113.0。"
     "同一段文本被读成两个前缀，意味着冲突检查问的是一条、装进去的是另一条。"),
    ("prefix", "203.0.113.0/08", "长度也一样，只接受一种写法"),
    ("address", "010.0.0.1", "同上，查下一跳这一侧"),
    ("prefix", "default", "表里的写法，不是规则的写法。规则一侧只接受 0.0.0.0/0。"),
    ("prefix", "", "空"),
    ("address", "8.8.8.8/32", "查下一跳要的是地址，不是前缀"),
    ("address", "8.8.8", "不是四个八位组"),
    ("address", " 8.8.8.8", "带空白"),
    ("interface", "-interface", "会被当成选项"),
    ("interface", "utun0 extra", "带空格"),
    ("interface", "以太网", "非 ASCII。Windows 上接口名必须转义，因为运维真的会用中文名和空格；"
                          "这边它是 argv 的一个元素，没什么可转义的，而内核的接口名本来就不长这样。"),
    ("interface", "0utun", "不以字母开头"),
    ("interface", "utun012345678901", "超过 IFNAMSIZ"),
    ("interface", "", "空"),
]:
    _refused = False
    try:
        if _kind == "prefix":
            install_interface_args(_value, "utun3")
        elif _kind == "address":
            find_route_args(_value)
        else:
            install_interface_args("203.0.113.0/24", _value)
    except ValueError:
        _refused = True
    assert _refused, "%s %r was not refused" % (_kind, _value)
    REJECTED_ARGUMENTS.append({"kind": _kind, "value": _value, "note": _note})

MALFORMED_PREFIX = {
    "description":
        "route -n add -net 203.0.113.0/33 <网关> 被接受了：打印「add net 203.0.113.0: gateway ...」，"
        "退出码 0，装进表里的是 128.0/1，也就是半个 IPv4 地址空间指向网关。"
        "输出里没有任何地方说得出这件事，只有路由表说得出。这就是为什么前缀校验发生在起进程之前，"
        "以及为什么它在 macOS 上不是「多一层防线」。",
    "command": " ".join(SAMPLED["route-add-malformed-prefix"]["argv"]),
    "stdout": SAMPLED["route-add-malformed-prefix"]["stdout"],
    "exit": SAMPLED["route-add-malformed-prefix"]["exit"],
    "installedPrefix": "128.0.0.0/1",
    "tableAfter": SAMPLED["netstat-rn-inet-final"]["stdout"],
    "sampled": True,
}

TUN_NEEDS_ADDRESS = {
    "description":
        "macOS 上 TUN 必须先有 IPv4 地址，路由才能指过去。同一条 "
        "route -n add -net 203.0.113.0/24 -interface utun3："
        "接口只有 IPv6 链路本地地址时报 Network is unreachable（退出码仍然是 0），"
        "ifconfig 配上 10.255.0.1 之后成功。Linux 上 ip route add ... dev tun0 不需要地址，"
        "所以这是一个平台差异，也是一个对调用顺序的要求：先配地址，再下发路由。",
    "withoutAddress": {
        "command": " ".join(SAMPLED["route-add-tun"]["argv"]),
        "stdout": SAMPLED["route-add-tun"]["stdout"],
        "stderr": SAMPLED["route-add-tun"]["stderr"],
        "exit": SAMPLED["route-add-tun"]["exit"],
        "ifconfig": SAMPLED["ifconfig-utun3-before"]["stdout"],
    },
    "withAddress": {
        "command": " ".join(SAMPLED["add-through-utun"]["argv"]),
        "stdout": SAMPLED["add-through-utun"]["stdout"],
        "stderr": SAMPLED["add-through-utun"]["stderr"],
        "exit": SAMPLED["add-through-utun"]["exit"],
        "ifconfig": SAMPLED["ifconfig-utun3-after"]["stdout"],
    },
    "sampled": True,
}

LOCALISATION = {
    "description":
        "同一条命令在 zh_CN.UTF-8、ja_JP.UTF-8、de_DE.UTF-8 下的输出与 C 区域逐字节相同。"
        "所以这边按键名解析是安全的，Windows 那边不是——那边同一条命令在一个控制台代码页下打印英文表头，"
        "另一个下打印中文表头。这是采样出来的，不是「BSD 工具没有消息目录」这个说法。",
    "locales": ["zh_CN.UTF-8", "ja_JP.UTF-8", "de_DE.UTF-8"],
    "identical": True,
    "sampled": True,
}

TIMINGS = {
    "description":
        "读表不缓存。netstat -rn -f inet 的中位数是 25 ms，route -n get 是 26 ms，"
        "/usr/bin/true 是 3 ms。Windows 那边缓存整表五秒，因为 PowerShell 一次查询 419 ms，"
        "二十条前缀的计划要花八秒去问；这边二十次读表是半秒。所以 macOS 不缓存："
        "缓存换来的是一个本来不存在的节省，代价是一个答案可能过期的窗口。",
    "netstatMedianMs": SAMPLED["timing-netstat-inet"]["elapsedMs"],
    "routeGetMedianMs": SAMPLED["timing-route-get"]["elapsedMs"],
    "processStartMedianMs": SAMPLED["timing-true"]["elapsedMs"],
    "cache": False,
    "sampled": True,
}

# ---------------------------------------------------------------------------------------------
# Self-checks. A vector that can be satisfied without doing the work is not pinning anything.
# ---------------------------------------------------------------------------------------------

assert any(c["expect"].get("parsed") and c["expect"]["gateway"] == "" for c in ROUTE_GET), \
    "no case exercises an on-link destination"
assert any(c["expect"].get("parsed") and c["expect"]["gateway"] for c in ROUTE_GET), \
    "no case has a gateway"
assert any(not c["expect"]["parsed"] for c in ROUTE_GET), "no case fails to parse"
assert any(c["expect"] == "" and c["input"].strip() for c in NORMALISE), \
    "no non-empty destination is rejected"
assert any("/" not in c["input"] and c["expect"].endswith("/24") for c in NORMALISE), \
    "no case needs the implied length"
assert any(c["input"] == "default" and c["expect"] == "0.0.0.0/0" for c in NORMALISE)
assert any(c["input"] == "10.1.2.3/8" and c["expect"] == "10.0.0.0/8" for c in NORMALISE), \
    "no case needs the address masked by the length"
assert any(c["expect"]["present"] and "(+2 more)" in c["expect"]["existing"]
           for c in CONFLICT), "no case reports a route count"
# The W filter has to change an answer, not just a count, or an implementation could skip it.
assert any(c["prefix"] == "192.168.64.255/32" and not c["expect"]["present"] for c in CONFLICT), \
    "nothing pins kernel-generated entries being excluded"
assert any(c["prefix"] == "0.0.0.0/1" and not c["expect"]["present"] for c in CONFLICT), \
    "nothing pins the exact-prefix comparison"
# The section gate likewise: the two-family case must find one default, not five.
_both = [c for c in CONFLICT if c["table"] == "netstat-rn-after" and c["prefix"] == "0.0.0.0/0"]
assert _both and _both[0]["expect"]["present"] and "(+" not in _both[0]["expect"]["existing"], \
    "nothing pins the IPv6 section being left out"
assert any(c["expect"]["failure"] == FAILURE_DENIED for c in COMMAND_RESULTS)
assert any(c["expect"]["failure"] == FAILURE_OTHER for c in COMMAND_RESULTS)
assert any(c["expect"]["failure"] == "" and NOT_IN_TABLE in c["stdout"] for c in COMMAND_RESULTS), \
    "nothing pins a removal of something already gone counting as success"
# A failure that exits 0. Without one, an implementation could read the exit status and pass.
assert any(c["expect"]["failure"] == FAILURE_OTHER and c["exit"] == 0 for c in COMMAND_RESULTS), \
    "nothing pins the exit status being unusable"
# And a success that exits 0 with a ": something" suffix nowhere in it, so the two are told apart
# by stderr rather than by the shape of the stdout line.
assert any(c["expect"]["failure"] == "" and not c["stderr"].strip() for c in COMMAND_RESULTS)
assert all(c.get("sampled") for c in COMMAND_RESULTS), "every command result must be sampled"
assert sum(1 for c in ROUTE_GET if c.get("sampled")) >= 10
assert any(r["kind"] == "prefix" and r["value"] == "203.0.113.0/33" for r in REJECTED_ARGUMENTS), \
    "the argument that installs half the internet is not in the refused list"
assert any(c["input"] == "010.0.0.1/8" and c["expect"] == "" for c in NORMALISE), \
    "nothing pins a leading zero being refused rather than read as decimal"
assert any(r["value"] == "010.0.113.0/24" for r in REJECTED_ARGUMENTS)
for _entry in COMMANDS["installInterface"]:
    assert _entry["argv"][:4] == ["route", "-n", "add", "-net"], _entry
for _entry in COMMANDS["remove"]:
    assert _entry["argv"] == ["route", "-n", "delete", "-net", _entry["prefix"]], _entry
assert show_table_args() == ["netstat", "-rn", "-f", "inet"]

vector = {
    "name": "peer-egress-macos-routes-v1",
    "version": 1,
    "notes": [
        "macOS 侧读路由表用 netstat -rn -f inet，改路由表用 route。标了 sampled 的输入是真机抓下来的"
        "原样输出，机器为 macOS 26.6.2（Darwin 25.6.0，arm64），采样脚本跑在 GitHub macos-latest 上。",
        "route 失败也返回 0。前缀已存在、前缀不在表里、接口没有地址、参数不合法——采样到的失败里"
        "除了地址不合法之外全部退出 0。分类不看退出码，看 stderr 是不是空的："
        "采样到的每一次成功修改 stderr 都是空的，每一次失败都有 route: writing to routing socket: ...。",
        "不按错误文本列表分类。那些错误是路由套接字返回值的 strerror，列不完；"
        "而没认出来的错误会被当成成功，那个方向留下的是「规则以为装上了，流量却从物理网卡出去」。"
        "stderr 上的噪声往另一个方向错：安装被报成失败，安装器把自己刚装的路由撤掉，什么都不会漏。",
        "route -n add -net 203.0.113.0/33 会被接受，打印成功行，装上 128.0/1。"
        "所以前缀校验在 macOS 上不是多一层防线，是唯一一层。",
        "输出不本地化，这是在三个 locale 下采样比对出来的，不是「BSD 工具没有消息目录」这个说法。",
        "不缓存整表。读一次 25 ms，Windows 那边是 419 ms——那边缓存五秒是省八秒，这边省不到什么，"
        "却要多一个答案可能过期的窗口。",
        "argv 直接 exec，没有 shell。所以这边没有引号问题：要防的是「读起来像选项的值」和"
        "「读起来像合法前缀但不是的值」。",
        "八位组和长度都不接受前导零。route 用 inet_aton 解析地址，前导零按八进制读，"
        "所以 010.0.0.1 对它是 8.0.0.1。要让同一段文本不产生两种读法，办法是只接受只有一种读法的写法。",
        "本文件的期望值出自 tools/protocol/generate_peer_egress_macos_route_vectors.py 里的"
        "独立参考实现，不是从任何一个实现录下来的。",
    ],
    "kernelGeneratedFlag": KERNEL_GENERATED_FLAG,
    "failureKinds": {"denied": FAILURE_DENIED, "other": FAILURE_OTHER},
    "routeGet": ROUTE_GET,
    "normalisePrefix": {
        "description":
            "netstat 的 Destination 列是缩写过的：0.0.0.0/0 写成 default，127.0.0.0/8 写成 127，"
            "203.0.113.0/24 写成 203.0.113，100.64.0.0/10 写成 100.64/10，"
            "198.51.100.0/26 写成 198.51.100/26，主机路由写成裸地址。读回来的规则是："
            "没带长度的按每个八位组八位算，带长度的把缺的八位组补零。补完之后还要按长度掩掉主机位——"
            "同一条前缀的两种写法必须比较相等，否则冲突检查回答的不是它被问的那个问题。",
        "cases": NORMALISE,
    },
    "table": TABLE,
    "bothFamilies": BOTH_FAMILIES,
    "duplicates": DUPLICATES,
    "tunRoute": TUN_ROUTE,
    "conflictFromTable": {
        "description":
            "冲突检查从整表里精确比较前缀，不做最长前缀查找。route -n get 根本回答不了这个问题："
            "问一个没有路由的地址，它返回默认路由。",
        "tables": {
            "netstat-rn-inet-after": SAMPLED["netstat-rn-inet-after"]["stdout"],
            "netstat-rn-inet-final": SAMPLED["netstat-rn-inet-final"]["stdout"],
            "netstat-rn-after": SAMPLED["netstat-rn-after"]["stdout"],
            "netstat-with-duplicates": SAMPLED["netstat-with-duplicates"]["stdout"],
            "netstat-after-one-delete": SAMPLED["netstat-after-one-delete"]["stdout"],
            "netstat-with-utun-route": SAMPLED["netstat-with-utun-route"]["stdout"],
        },
        "cases": CONFLICT,
    },
    "commandResults": COMMAND_RESULTS,
    "commands": {
        "description":
            "发出去的 argv 也钉住，不只是收回来的输出。三端各自拼一份参数，"
            "正是其中两端用了 -net 而第三端用了 -host 的方式，而输出里看不出差别。",
        "showTable": COMMANDS["showTable"],
        "findRoute": COMMANDS["findRoute"],
        "installInterface": COMMANDS["installInterface"],
        "installGateway": COMMANDS["installGateway"],
        "remove": COMMANDS["remove"],
        "rejectedArguments": REJECTED_ARGUMENTS,
    },
    "malformedPrefix": MALFORMED_PREFIX,
    "tunNeedsAddress": TUN_NEEDS_ADDRESS,
    "localisation": LOCALISATION,
    "timings": TIMINGS,
    "provenance": {
        "swVers": SAMPLED["provenance-sw-vers"]["stdout"],
        "uname": SAMPLED["provenance-uname"]["stdout"],
    },
}

out = VECTORS / "peer-egress-macos-routes-v1.json"
out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", out, out.stat().st_size, "bytes")
print("routeGet:", len(ROUTE_GET), "normalise:", len(NORMALISE), "conflict:", len(CONFLICT),
      "commandResults:", len(COMMAND_RESULTS), "rejected:", len(REJECTED_ARGUMENTS))
print("table rows:", TABLE["expect"]["rows"], "both-family rows:", BOTH_FAMILIES["expect"]["rows"],
      "duplicate rows:", DUPLICATES["expect"]["rows"])
