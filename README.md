# fi6s: Fast IPv6 scanner

fi6s is a IPv6 port scanner designed to be fast.
This is achieved by sending and processing raw packets asynchronously.
The design and goal is pretty similar to [Masscan](https://github.com/robertdavidgraham/masscan),
though it has not reached a similar feature set yet.

## Building

Building should be fairly easy **IF** your software is recent enough:
On Ubuntu 16.04 (xenial) it looks like this:

	# apt install gcc make git libpcap-dev
	$ git clone https://github.com/sfan5/fi6s.git
	$ cd fi6s
	$ make BUILD_TYPE=release

The scanner executable will be ready in at `./fi6s`.
Note that fi6s is developed solely on Linux, thus
it might not work on non-Linux OSs (*BSD, macOS or Windows) at all.

## Usage

Usage is pretty easy, fi6s will try to auto-detect the
dirty technical details (source/dest MAC, source IP).

	# ./fi6s -p 80,8000-8100 2001:db8::/120

This example will:
* scan the 2001:db8::/120 subnet (256 addresses in total)
* scans port 80 and ports 8000 to 8100 (102 ports in total)
* outputs scan results to `stdout`

There's more different ways of specifying a range of addresses to scan,
if you aren't sure what's about to happen invoke fi6s with `--echo-hosts`
and it will print every host that will be scanned.

For advanced features please consult the output of `./fi6s -h`.

## Grabbing banners

Since fi6s has its own TCP stack, the OS stack needs to disabled to avoid interference
with banner grabbing (RST packets).
This is most easily done using ip6tables and a constant `--source-port`.
Banner grabbing is then enabled by passing `--banners`:

	# ip6tables -A INPUT -p tcp -m tcp --dport 12345 -j DROP
	# ./fi6s -p 22 --banners --source-port 12345 2001:db8::/120
