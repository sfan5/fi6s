# fi6s: Fast IPv6 scanner

fi6s is a IPv6 port scanner designed to be fast.
This is achieved by sending and processing raw packets asynchronously.
The design and goal is pretty similar to [Masscan](https://github.com/robertdavidgraham/masscan),
though it has not reached a similar feature set yet.

## Building

Building should be fairly easy *IF* your software is recent enough:
On Ubuntu 16.04 (xenial) it looks like this:

	# apt install gcc make git libpcap-dev
	$ git clone $REPO_URL
	$ cd fi6s
	$ make BUILD_TYPE=release

The scanner executable will be ready in at `./fi6s`.
Note that support for non-Linux OSs is not a priority,
which means that it might not work on *BSD or Windows at all.

## Usage

Theoretically usage is pretty easy, however right now you
need to specify adapter MACs and source IP manually.

	# ./fi6s --source-mac 11:22:33:44:55:66 --router-mac 66:55:44:33:22:11 --source-ip 2001:db8::1 -p 80,8000-8100 2001:db8::/120

This example will:
* scan the 2001:db8::/120 subnet (256 addresses in total)
* scans port 80 and ports 8000 to 8100 (102 ports in total)
* outputs scan results to `stdout`

There's more different ways of specifying a range of addresses to scan,
if you aren't sure what's about to happen invoke fi6s with `--echo-hosts`
and it will print every host that will be scanned.

For advanced features please consult the output of `./fi6s -h`.
