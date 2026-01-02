#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
import sys
import os
import struct
from hashlib import md5

FILE_MAGIC = 0x4e414373
RECORD_ALIGN = 8

# struct file_header {
#	uint32_t magic;
#	uint16_t version;
# }
# struct rec_header {
#	uint64_t timestamp;
#	uint32_t size; // incl. header
#	uint16_t port;
#	uint8_t ttl; // ignored for banner records
#	uint8_t proto_status; // (proto << 4) | status; status is ignored for banner records
#	uint8_t addr[16];
#	// banner data follows here
# }

def skip_align(f, read: int):
	have = read % RECORD_ALIGN
	if have > 0:
		f.read(RECORD_ALIGN - have)

def readpacked(f, fmt: str, align=False) -> tuple:
	n = struct.calcsize(fmt)
	data = f.read(n)
	if not data:
		return
	if align:
		skip_align(f, n)
	return struct.unpack(fmt, data)

def reader(fi, proto, port):
	fmt = "<QLHBB16s"
	hlen = struct.calcsize(fmt)
	assert hlen == 32
	n = 0
	seen = set()
	os.makedirs("sample", exist_ok=True)
	while True:
		data = readpacked(fi, fmt)
		if not data: break
		if data[1] > hlen:
			buf = fi.read(data[1] - hlen)
		else:
			buf = b""
		skip_align(fi, data[1])

		if len(buf) == 0:
			continue
		if data[2] != port or (data[4] >> 4) != proto:
			continue

		hhh = md5(buf).digest()[:8]
		if hhh in seen:
			continue
		seen.add(hhh)
		n += 1

		with open("sample/%04d.bin" % n, "wb") as fo:
			fo.write(buf)
	return n

def main(args):
	with open(args[0], "rb") as fi:
		hmagic, hver = readpacked(fi, "<LH", True)
		assert hmagic == FILE_MAGIC
		assert hver == 1

		n = reader(fi, dict(tcp=0, udp=1)[args[1]], int(args[2]))

	print("Extracted %d unique banners" % n)

if __name__ == "__main__":
	if len(sys.argv) < 4:
		print("Usage: extract.py <input .bin> <tcp / udp> <port>")
		exit(1)
	main(sys.argv[1:])
	exit(0)
