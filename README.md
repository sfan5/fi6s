# fi6s: Fast IPv6 scanner

fi6s is a IPv6 port scanner designed to be fast.
This is achieved by sending and processing raw packets asynchronously.
The design and goal is pretty similar to [Masscan](https://github.com/robertdavidgraham/masscan),
though it is not as full-featured yet.

## Building

Building is fairly easy on any recent Linux system, e.g. on Ubuntu:

	# apt install gcc make git libpcap-dev
	$ git clone https://github.com/sfan5/fi6s.git
	$ cd fi6s
	$ make BUILD_TYPE=release

The scanner executable will be ready in at `./fi6s`.
Note that fi6s is developed solely on Linux, thus it probably won't compile on non-Linux OSs (notably Windows).

## Usage

Usage is pretty easy, fi6s will try to auto-detect the dirty technical details
such as source, router MAC addresses and source IP.

	# ./fi6s -p 80,8000-8100 2001:db8::/120

This example will:
* scan the 2001:db8::/120 subnet (256 addresses in total)
* scans port 80 and ports 8000 to 8100 (102 ports in total)
* output scan results to `stdout` in the "`list`" format

There are more different ways of specifying an address range to scan,
if you aren't sure what's about to happen invoke fi6s with `--print-hosts`
to print all IPs or `--print-summary` to get a quick overview about the scan.

For more advanced features please consult the output of `fi6s --help`.

## Grabbing banners

Since fi6s has its own TCP stack, the OS stack needs to disabled to avoid interference
with banner grabbing (RST packets). This is most easily done using ip6tables
and a constant `--source-port`.

Banner grabbing is then enabled by passing `--banners`:

	# ip6tables -A INPUT -p tcp -m tcp --dport 12345 -j DROP
	# ./fi6s -p 22 --banners --source-port 12345 2001:db8::xx
