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

## Grabbing banners

Since fi6s has its own TCP stack, the OS' stack needs to disabled to avoid
interference with banner grabbing (RST packets). This is easily done using
ip6tables and a constant `--source-port`.

Banner grabbing is then enabled by passing `--banners`:

	# ip6tables -A INPUT -p tcp -m tcp --dport 12345 -j DROP
	# ./fi6s -p 22 --banners --source-port 12345 2001:db8::xx

### UDP

Dropping packets before they reach the OS stack is not required for UDP scans, but
is still a good idea to avoid a flood of ICMPv6 unreachable responses.

Other than that you only need an additional `--udp`:

	# ip6tables -A INPUT -p udp -m udp --dport 12345 -j DROP
	# ./fi6s -p 53 --banners --udp --source-port 12345 2001:db8::xx

Note that unlike with TCP, you will only get useful (or any) results if you scan
a port whose protocol is supported by fi6s. You can use `fi6s --list-protocols`
to view a list.
