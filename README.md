# fi6s: Fast IPv6 scanner

fi6s is an IPv6 port scanner designed to be fast, aimed at Internet scanning and discovery.
This is achieved by sending and processing raw packets asynchronously.

The design and goal is pretty similar to [Masscan](https://github.com/robertdavidgraham/masscan),
though it is not as full-featured.

Please take note of the [license](./LICENSE).

Finally: This is a security research tool and you (the user) are fully responsible
for following local regulations and obtaining permission as necessary when using it.

## Compiling

Building fi6s is fairly easy on any recent Linux system, e.g. on Ubuntu:

	# apt install gcc make git libpcap-dev
	$ git clone https://github.com/sfan5/fi6s.git
	$ cd fi6s
	$ make BUILD_TYPE=release

The scanner executable will be ready at `./fi6s`.

Note that fi6s is developed and tested solely on Linux. Other UNIX-like platforms
*should* work, Windows will not.

## Usage

fi6s will auto-detect the dirty network details (source, router MACs and IPs) for you, so you can jump right into scanning:

	# ./fi6s -p 80,8000-8100 --max-rate 170 2001:db8::/120

This example will:
* scan the 2001:db8::/120 subnet (256 addresses in total)
* scan TCP ports 80 and 8000 to 8100 (102 ports in total)
* send at most 170 packets per second
* output scan results to standard output in the "`list`" format

There are more different ways of specifying an address range to scan,
if you aren't sure what's about to happen use `--print-summary` to get a quick
overview about the scan or `--print-hosts` to print all potential target IPs.

For more advanced features and additional explanations please consult the output of `fi6s --help`.

## Collecting banners

The data a remote host sends in response to a new connection or probe request
is called a "banner". fi6s makes it easy to collect them.

All you need to do is pass the `--banners` option:

	# ./fi6s -p 22 --banners 2001:db8::xx

### UDP

Add the `--udp` flag to your command line:

	# ./fi6s -p 53 --banners --udp 2001:db8:xx::1

Note that unlike TCP, you will only get useful (or any) results if you scan
a port whose protocol is supported for probing by fi6s.
Use `fi6s --list-protocols` to view a list.

### The source port and the IP stack

Since fi6s brings its own minimal TCP/IP stack the operating system has to be prevented
from trying to talk TCP on the same port fi6s is using, or it would break the scanning process.

By default fi6s will ask the OS to reserve an ephemeral port and use it for the
duration of the scan. This only works on Linux.

If this fails or you are on a different platform (*fi6s will tell you!*)
you have to decide on a source port and configure your firewall to drop all
traffic on this port, e.g.:

	# ipfw add 1000 deny tcp from any to any 12345 in ip6
	or:
	# ip6tables -A INPUT -p tcp -m tcp --dport 12345 -j DROP
	and then:
	# ./fi6s -p 22 --banners --source-port 12345 2001:db8::xx

Since UDP is connection-less there is no need to do this, but it's still
a good idea to prevent your OS from sending unnecessary ICMPv6 unreachable
responses. fi6s will also do this by default.

### Selecting the source IP

A big advantage of IPv6 is the large address space, and another way of avoiding
the problem described above is to just use a different source IP.

This IP should not be assigned to your local machine, but it **must** be statically routed
to your machine, because fi6s will not answer NDP queries.

To check if your setup is working correctly you can simply ping a known public IP, e.g.:

	# ./fi6s --icmp --source-ip ${chosen_src_ip} 2001:4860:4860::8888

## ICMP

Use `--icmp` to do an ICMPv6 Ping scan:

	# ./fi6s --icmp 2001:xxx0::1

The round trip time will not be measured.

## Limitations

In order to permit the design of fi6s some assumptions had to be made about
the network environment. These do not impact typical usage at all but are listed
here for completeness.

This means fi6s may not perform as expected or outright not work if:
* you have a non-trivial routing table (it will be ignored. fi6s expects a single gateway)
* you are scanning targets in the local network (fi6s does not do neighbor discovery)
* you have a connection-tracking firewall
* your IP or router's MAC changes mid-scan ¯\\\_(ツ)_/¯
* your network has consistent packet loss

For banner collection note that fi6s does not come with anything resembling a real TCP
stack. It merely supports sending one query and reading response data that follows.
Resends or window logic are not implemented.

### Scanned IP vs response IP

While fi6s uses port and sequence numbers to ensure that the results you get are
related to the specific running scan, it does **not** have a check to
compare the IP a probe was sent to with the IP that is actually responding.

This means if you e.g. run ping or a traceroute during an ICMP scan, the
results will *not* be contaminated.

However it *is possible* for `2001:db8:f00::1` to show up in the scan results
despite specifying `2001:db8:0::/116` as target subnet.
This property can be useful in practice, since some routers will accept SNMP or
DNS queries on the zero network address, but answer with their primary IPv6.

Example: scan `3fff:1234:1234:44xx::` -> response from `3fff:1234:1234:44a3:e2a:86ff:fe12:3456`

### Target randomization

The way fi6s randomizes the scanned IPs (`--randomize-hosts 1`, which is the default)
is not perfect.

It will:
* shuffle IPs in batches of 8192
* evenly distribute multiple targets over the duration of the scan (like round-robin)
* however still traverse subnets *sequentially*

For example if you scan `3fff::/108` the order of `3fff::1`, `3fff::20` and `3fff::300` will be random.
But all addresses in `3fff::0:*` will be scanned before `3fff::1:*`, before `3fff::2:*` and so on.
