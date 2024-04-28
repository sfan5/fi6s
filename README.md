# fi6s: Fast IPv6 scanner

fi6s is an IPv6 port scanner designed to be fast.
This is achieved by sending and processing raw packets asynchronously.
The design and goal is pretty similar to [Masscan](https://github.com/robertdavidgraham/masscan),
though it is not as full-featured yet.

## Compiling

Building fi6s is fairly easy on any recent Linux system, e.g. on Ubuntu:

	# apt install gcc make git libpcap-dev
	$ git clone https://github.com/sfan5/fi6s.git
	$ cd fi6s
	$ make BUILD_TYPE=release

The scanner executable will be ready at `./fi6s`.

Note that fi6s is developed and tested solely on Linux. It *should* work on other
UNIX-like platforms, but don't expect it to run on Windows.

## Usage

Usage is pretty easy, fi6s will try to auto-detect the dirty technical details
such as source, router MAC addresses and source IP.

	# ./fi6s -p 80,8000-8100 --max-rate 170 2001:db8::/120

This example will:
* scan the 2001:db8::/120 subnet (256 addresses in total)
* scan TCP ports 80 and 8000 to 8100 (102 ports in total)
* send at most 170 packets per second
* output scan results to standard output in the "`list`" format

There are more different ways of specifying an address range to scan,
if you aren't sure what's about to happen run fi6s with `--print-summary` to get
a quick overview about the scan or `--print-hosts` to print all potential IPs.

For more advanced features please consult the output of `fi6s --help`.

## Collecting banners

The data a remote host sends in response to a new connection or probe request
is called "banner". fi6s makes it easy to collect these.

All you need to do is pass the `--banners` option:

	# ./fi6s -p 22 --banners 2001:db8::xx

### UDP

Add the `--udp` flag to your command line:

	# ./fi6s -p 53 --banners --udp 2001:db8::xx

Note that unlike TCP, you will only get useful (or any) results if you scan
a port whose protocol is supported for probing by fi6s.
Use `fi6s --list-protocols` to view a list.

### The source port and the IP stack

Since fi6s brings its own minimal TCP/IP stack the operating system has to be prevented
from trying to talk TCP on the same port fi6s is using, or it would break the scanning process.
It would typically send RST frames in this case.

By default fi6s will ask the OS to reserve an ephemeral port and use it for the
duration of the scan. This only works on Linux.

If this doesn't work or you are on a different platform you will have to use a static
source port and configure your firewall to drop traffic on this port, e.g.:

	# ip6tables -A INPUT -p tcp -m tcp --dport 12345 -j DROP
	# ./fi6s -p 22 --banners --source-port 12345 2001:db8::xx

Since UDP is connection-less there is no need to prevent interference, though this
is still a good idea to prevent your OS from sending unnecessary ICMPv6 unreachable
responses (fi6s also tries this by default).
