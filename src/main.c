#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "util.h"
#include "target.h"

void usage(void)
{
	printf("fi6s is a IPv6 network scanner aimed at scanning lots of hosts in litte time.\n");
	printf("Usage: fi6s [options] <target specification>\n");
	printf("Options:\n");
	printf("  --help                  Show this text\n");
	printf("  --randomize-hosts <0|1> Randomize order of hosts (defaults to 1)\n");
	printf("  --echo-hosts            Print all hosts to be scanned to stdout and exit\n");
	printf("  -p <port range(s)>      Only scan specified ports\n");
	printf("  --max-rate <n>          Send no more than <n> packets per second\n");
	printf("  --output-format <fmt>   Set output format to list/json/binary (defaults to list)\n");
	printf("  -o <file>               Set output file\n");
	printf("Target specification:\n");
	printf("  A target specification is basically just a fancy netmask.\n");
	printf("  Target specs come in three shapes:\n");
	printf("    2001:db8::/64 (classic subnet notation)\n");
	printf("      It should be obvious how this one works...\n");
	printf("    2001:db8::1/32-48 (subnet range notation)\n");
	printf("      The resulting netmask will be ffff:ffff:0000:ffff:ffff:ffff:ffff:ffff\n");
	printf("      This will return all hosts 2001:db8:*::1 with * in range 0000 to ffff\n");
	printf("    2001:db8::x (wildcard nibble notation)\n");
	printf("      The resulting netmask will be all f's except the last nibble\n");
	printf("      This will return all hosts 2001:db::* with * in range 0 to f\n");
	printf("  It is only possible to specify one target specification on the command line,\n");
	printf("  if you want to scan multiple save them to a file and pass @/path/to/file.txt to fi6s.\n");
}

int mainloop(void);

int main(int argc, char *argv[])
{
	const struct option long_options[] = {
		{"randomize-hosts", required_argument, 0, 'Z'},
		{"echo-hosts", no_argument, 0, 'Y'},
		{"max-rate", required_argument, 0, 'X'},
		{"output-format", required_argument, 0, 'W'},

		{"help", no_argument, 0, 'h'},
		{"output-file", required_argument, 0, 'o'},
		{0,0,0,0},
	};
	int echo_hosts = 0;

	while(1) {
		int c = getopt_long(argc, argv, "hp:o:", long_options, NULL);
		if(c == -1)
			break;
		switch(c) {
			case 'Z': {
				int val = atoi(optarg);
				if(val != 0 && val != 1) {
					printf("Argument to --randomize-hosts must be 0 or 1\n");
					return 1;
				}
				// TODO
				break;
			}
			case 'Y':
				echo_hosts = 1;
				break;
			case 'X': {
				int val = strtol_suffix(optarg);
				if(val <= 0) {
					printf("Argument to --max-rate must be positive\n");
					return 1;
				}
				// TODO
				break;
			}
			case 'W':
				if(strcmp(optarg, "list") != 0 &&
					strcmp(optarg, "json") != 0 &&
					strcmp(optarg, "binary") != 0) {
					printf("Argument to --output-format must be one of list, json or binary\n");
				}
				// TODO
				break;

			case 'h':
				usage();
				return 1;
			case 'p':
				// TODO
				break;
			case 'o':
				// TODO
				break;
			default:
				break;
		}
	}
	if(argc - optind != 1) {
		printf("One target specification required\n");
		return 1;
	}

	if(echo_hosts) {
		struct targetspec t;
		if(target_parse(argv[optind], &t) < 0) {
			printf("Failed to parse target spec.\n");
			return 1;
		}
		printf("addr= ");
		for(int i = 0; i < 16; i+=2)
			printf("%02x%02x%c", t.addr[i], t.addr[i+1], (i == 14)?'\n':':');
		printf("mask= ");
		for(int i = 0; i < 16; i+=2)
			printf("%02x%02x%c", t.mask[i], t.mask[i+1], (i == 14)?'\n':':');
		return 0;
	}
	return mainloop();
}

int mainloop(void)
{
	// Do actual stuff here...
	return 123;
}
