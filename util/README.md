## Utilities

**`bin2pcap.py`**:

This script can convert the response banners recorded in a binary scan file into a
standard PCAP. This is very useful for further analysis in Wireshark.

Note that fi6s does not record TCP conversations or even the source IP, port, TTLs
and many other protocol details so these will be filled with dummy data.
Timestamps are available however.

**`ci-test.sh` et al**:

Integration tests for CI
