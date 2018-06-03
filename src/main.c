#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h> // getpid()
#include <time.h> // time()
#include <getopt.h>
#include <netinet/in.h> // struct sockaddr_in6, AF_INET6

#include "util.h"
#include "target.h"
#include "rawsock.h"
#include "scan.h"
#include "output.h"

static void usage(void);
static bool is_allFF(const uint8_t *buf, int len);
static void trim(char *buf, const char *trimchars);

int main(int argc, char *argv[])
{
	const struct option long_options[] = {
		{"randomize-hosts", required_argument, 0, 'Z'},
		{"echo-hosts", no_argument, 0, 'Y'},
		{"max-rate", required_argument, 0, 'X'},
		{"output-format", required_argument, 0, 'W'},
		{"interface", required_argument, 0, 'V'},
		{"source-mac", required_argument, 0, 'U'},
		{"router-mac", required_argument, 0, 'T'},
		{"source-ip", required_argument, 0, 'S'},
		{"source-port", required_argument, 0, 'R'},
		{"ttl", required_argument, 0, 'Q'},
		{"show-closed", no_argument, 0, 'P'},
		{"readscan", required_argument, 0, 'O'},

		{"help", no_argument, 0, 'h'},
		{"output-file", required_argument, 0, 'o'},
		{"banners", no_argument, 0, 'b'},
		{"udp", no_argument, 0, 'u'},
		{0,0,0,0},
	};

	int echo_hosts = 0, randomize_hosts = 1,
		ttl = 64, max_rate = -1,
		source_port = -1, quiet = 0,
		show_closed = 0, banners = 0,
		udp = 0;
	uint8_t source_mac[6], router_mac[6], source_addr[16];
	char *interface = NULL;
	struct ports ports;
	FILE *outfile = stdout, *readscan = NULL;
	const struct outputdef *outdef = &output_list;

	memset(source_mac, 0xff, 6);
	memset(router_mac, 0xff, 6);
	memset(source_addr, 0xff, 16);
	init_ports(&ports);
	while(1) {
		int c = getopt_long(argc, argv, "hp:o:qbu", long_options, NULL);
		if(c == -1)
			break;
		switch(c) {
			case 'Z':
				if(strlen(optarg) > 1 || (*optarg != '0' && *optarg != '1')) {
					printf("Argument to --randomize-hosts must be 0 or 1\n");
					return 1;
				}
				randomize_hosts = (*optarg == '1');
				break;
			case 'Y':
				echo_hosts = 1;
				break;
			case 'X': {
				int val = strtol_suffix(optarg);
				if(val <= 0) {
					printf("Argument to --max-rate must be a positive number\n");
					return 1;
				}
				max_rate = val;
				break;
			}
			case 'W':
				if(strcmp(optarg, "list") == 0) {
					outdef = &output_list;
				} else if(strcmp(optarg, "json") == 0) {
					outdef = &output_json;
				} else if(strcmp(optarg, "binary") == 0) {
					outdef = &output_binary;
				} else {
					printf("Argument to --output-format must be one of list, json or binary\n");
					return 1;
				}
				break;
			case 'V':
				interface = optarg;
				break;
			case 'U':
				if(parse_mac(optarg, source_mac) < 0) {
					printf("Argument to --source-mac is not a valid MAC address\n");
					return 1;
				}
				break;
			case 'T':
				if(parse_mac(optarg, router_mac) < 0) {
					printf("Argument to --router-mac is not a valid MAC address\n");
					return 1;
				}
				break;
			case 'S':
				if(parse_ipv6(optarg, source_addr) < 0) {
					printf("Argument to --source-ip is not a valid IPv6 address\n");
					return 1;
				}
				break;
			case 'R': {
				int val = strtol_simple(optarg, 10);
				if(val < 1 || val > 65535) {
					printf("Argument to --source-port must be a number in range 1-65535\n");
					return 1;
				}
				source_port = val;
				break;
			}
			case 'Q': {
				int val = strtol_simple(optarg, 10);
				if(val < 1 || val > 255) {
					printf("Argument to --ttl must be a number in range 1-255\n");
					return 1;
				}
				ttl = val;
				break;
			}
			case 'P':
				show_closed = 1;
				break;
			case 'O': {
				FILE *f = fopen(optarg, "rb");
				if(!f) {
					printf("Failed to open scan file for reading.\n");
					return 1;
				}
				readscan = f;
				break;
			}

			case 'h':
				usage();
				return 1;
			case 'p':
				if(parse_ports(optarg, &ports) < 0) {
					printf("Argument to -p must be valid port range(s)\n");
					return 1;
				}
				break;
			case 'o': {
				FILE *f = fopen(optarg, "wb");
				if(!f) {
					printf("Failed to open output file for writing.\n");
					return 1;
				}
				outfile = f;
				break;
			}
			case 'q':
				quiet = 1;
				break;
			case 'b':
				banners = 1;
				break;
			case 'u':
				udp = 1;
				break;
			default:
				break;
		}
	}
	if(!readscan && argc - optind != 1) {
		printf("One target specification required\n");
		return 1;
	}

	// attempt to auto-detect a few arguments
	if(!echo_hosts && !readscan) {
		if(!interface) {
			if(rawsock_getdev(&interface) < 0)
				return -1;
			fprintf(stderr, "Using default interface '%s'\n", interface);
		}
		if(is_allFF(source_mac, 6))
			rawsock_getmac(interface, source_mac);
		if(is_allFF(router_mac, 6))
			rawsock_getgw(interface, router_mac);
		if(is_allFF(source_addr, 16)) {
			struct sockaddr_in6 globaddr;
			memset(&globaddr, 0, sizeof(struct sockaddr_in6));
			globaddr.sin6_family = AF_INET6;
			globaddr.sin6_addr.s6_addr[0] = 0x20; // 2000::
			rawsock_getsrcip(&globaddr, source_addr);
		}
	}

	srand(time(NULL) ^ getpid());
	if(target_gen_init() < 0)
		return 1;
	target_gen_set_randomized(randomize_hosts);
	rawsock_eth_settings(source_mac, router_mac);
	rawsock_ip_settings(source_addr, ttl);

	const char *tspec = argv[optind];
	if(readscan != NULL) {
		// no targets in this mode
	} else if(*tspec == '@') { // load from file
		FILE *f;
		char buf[128];
		f = fopen(&tspec[1], "r");
		if(!f) {
			printf("Failed to open target list for reading.\n");
			return 1;
		}
		while(fgets(buf, sizeof(buf), f) != NULL) {
			struct targetspec t;

			trim(buf, " \t\r\n");
			if(buf[0] == '#' || buf[0] == '\0')
				continue; // skip comments and empty lines

			if(target_parse(buf, &t) < 0) {
				printf("Failed to parse target spec \"%s\".\n", buf);
				fclose(f);
				return 1;
			}
			if(target_gen_add(&t) < 0) {
				fclose(f);
				return 1;
			}
		}
		fclose(f);
	} else { // single target spec
		struct targetspec t;
		if(target_parse(tspec, &t) < 0) {
			printf("Failed to parse target spec.\n");
			return 1;
		}
		target_gen_add(&t);
	}

	int r;
	if(readscan != NULL) {
		scan_reader_set_general(show_closed, banners);
		scan_reader_set_output(outfile, outdef);
		r = scan_reader_main(readscan) < 0 ? 1 : 0;
	} else if(echo_hosts) {
		uint8_t addr[16];
		char buf[IPV6_STRING_MAX];
		while(target_gen_next(addr) == 0) {
			ipv6_string(buf, addr);
			puts(buf);
		}

		r = 0;
	} else {
		// complain about missing args
		const char* missing = NULL;
		if(is_allFF(source_mac, 6))
			missing = "--source-mac";
		else if(is_allFF(router_mac, 6))
			missing = "--router-mac";
		else if(is_allFF(source_addr, 16))
			missing = "--source-ip";
		else if(!validate_ports(&ports))
			missing = "-p";
		else if(banners && !udp && source_port == -1)
			missing = "--source-port";

		if(missing) {
			printf("Option %s is required but was not given.\n", missing);
			r = 1;
		} else {
			scan_set_general(&ports, max_rate, show_closed, banners);
			scan_set_network(source_addr, source_port, udp ? IP_TYPE_UDP : IP_TYPE_TCP);
			scan_set_output(outfile, outdef);
			r = scan_main(interface, quiet) < 0 ? 1 : 0;
		}
	}

	target_gen_fini();
	fclose(outfile);
	if(readscan != NULL)
		fclose(readscan);
	return r;
}

static void usage(void)
{
	printf("fi6s is a IPv6 network scanner aimed at scanning lots of hosts in little time.\n");
	printf("Usage: fi6s [options] <target specification>\n");
	printf("Options:\n");
	printf("  --help                  Show this text\n");
	printf("  --readscan <file>       Read specified binary scan instead of scanning\n");
	printf("  --randomize-hosts <0|1> Randomize scan order of hosts (enabled by default)\n");
	printf("  --echo-hosts            Print all hosts to be scanned to stdout and exit\n");
	printf("  --max-rate <n>          Send no more than <n> packets per second\n");
	printf("  --source-port <port>    Use specified source port for scanning\n");
	printf("  --interface <if>        Use <if> for capturing and sending packets\n");
	printf("  --source-mac <mac>      Set Ethernet layer source to <mac>\n");
	printf("  --router-mac <mac>      Set Ethernet layer destination to <mac>\n");
	printf("  --source-ip <ip>        Use specified source IP for scanning\n");
	printf("  --ttl <n>               Set Time-To-Live of sent packets to <n> (defaults to 64)\n");
	printf("  -p <port range(s)>      Specify ports to scan (\"-\" is short for 1-65535)\n");
	printf("  --output-format <fmt>   Set output format to list/json/binary (defaults to list)\n");
	printf("  -o <file>               Set output file\n");
	printf("  --show-closed           Output closed ports (RSTs)\n");
	printf("  --banners               Capture banners\n");
	printf("  -q                      Do not output periodic status message\n");
	printf("Target specification:\n");
	printf("  A target specification is basically just a fancy netmask.\n");
	printf("  Target specs come in three shapes:\n");
	printf("    2001:db8::/64 (classic subnet notation)\n");
	printf("      This one should be obvious, you can even omit the number (it defaults to 128).\n");
	printf("    2001:db8::1/32-48 (subnet range notation)\n");
	printf("      The resulting netmask will be ffff:ffff:0000:ffff:ffff:ffff:ffff:ffff\n");
	printf("      This will return all hosts 2001:db8:*::1 with * in range 0000 to ffff\n");
	printf("    2001:db8::x (wildcard nibble notation)\n");
	printf("      The resulting netmask will be all f's except the last nibble\n");
	printf("      This will return all hosts 2001:db8::0, 2001:db8::1 ... 2001:db8::f\n");
	printf("  It is only possible to specify one target specification on the command line,\n");
	printf("  if you want to scan multiple save them to a file and pass @/path/to/file.txt to fi6s.\n");
	printf("Binary scan output:\n"); // TODO: this section sucks
	printf("  The binary output format is special.\n");
	printf("  During scanning banners will not be decoded or changed and are written in full.\n");
	printf("  Afterwards binary scans can be read again and output in any other format.\n");
	printf("  Options such as --banners and --show-closed can be applied both during scanning and reading.\n");
	printf("  For example, both given command lines result in the same kind of output:\n");
	printf("    fi6s -o scan.bin --output-format binary -b --show-closed 2001:db8::xx && fi6s -o final.txt --show-closed --readscan scan.bin\n");
	printf("      First, scan the given subnet with banners and closed ports enabled. Second, filter banners but output closed ports.\n");
	printf("    fi6s -o final.txt --show-closed 2001:db8::xx\n");
	printf("      Scan with closed ports enabled, gives the same results as above\n");
}

static bool is_allFF(const uint8_t *buf, int len)
{
	while(len--) {
		if(*(buf++) != 0xff)
			return false;
	}
	return true;
}

static void trim(char *buf, const char *trimchars)
{
	// front
	int i = 0;
	while(buf[i] && strchr(trimchars, buf[i]))
		i++;
	if(i > 0)
		memmove(buf, &buf[i], strlen(buf) + 1 - i);

	// back
	char *ptr = buf + strlen(buf) - 1;
	while(ptr > buf && strchr(trimchars, *ptr))
		ptr--;
	*(ptr + 1) = '\0';
}
