#!/usr/bin/env python3
import sys
import struct
from typing import BinaryIO

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

def skip_align(f: BinaryIO, read: int):
	have = read % RECORD_ALIGN
	if have > 0:
		f.read(RECORD_ALIGN - have)

def readpacked(f: BinaryIO, fmt: str, align=False) -> tuple:
	n = struct.calcsize(fmt)
	data = f.read(n)
	if not data:
		return
	if align:
		skip_align(f, n)
	return struct.unpack(fmt, data)

def readinto(f: BinaryIO, to: bytearray, n: int) -> memoryview:
	if n == 0:
		return memoryview(b"")
	assert len(to) >= n
	view = memoryview(to)[:n]
	f.readinto(view)
	return view

def make_tcp(sport: int, datalen: int) -> bytes:
	return struct.pack("!HHLLBBHHH", sport, 60001, 0xdeadbeef, 0, 5 << 4,
		1 << 3, 9999, 0xffff, 0)

def make_udp(sport: int, datalen: int) -> bytes:
	return struct.pack("!HHHH", sport, 60001, 8 + datalen, 0xffff)

def convert(fi: BinaryIO, fo: BinaryIO):
	fmt = "<QLHBB16s"
	hlen = struct.calcsize(fmt)
	assert hlen == 32
	n = 0
	buf = bytearray(10240)
	while True:
		data = readpacked(fi, fmt)
		if not data: break
		my_buf = readinto(fi, buf, max(0, data[1] - hlen))
		skip_align(fi, data[1])

		if len(my_buf) == 0: continue
		proto = data[4] >> 4
		if proto == 0:
			fakepkt = make_tcp(data[2], len(my_buf))
			nproto = 6 # IPPROTO_TCP
		elif proto == 1:
			fakepkt = make_udp(data[2], len(my_buf))
			nproto = 17 # IPPROTO_UDP
		else:
			continue

		fakehdr = struct.pack("!BxxxHBB", 6 << 4, len(fakepkt) + len(my_buf), nproto, 64)
		fakehdr += data[5] # source addr
		fakehdr += b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" # dest addr

		timestamp = data[0] if data[0] < 0xffffffff else 0xffffffff
		total = len(fakehdr) + len(fakepkt) + len(my_buf)
		pcaphdr = struct.pack("<LLLL", timestamp, 0, total, total)

		fo.write(pcaphdr + fakehdr + fakepkt)
		fo.write(my_buf)
		n += 1
	return n

def main(filename_in, filename_out):
	with open(filename_in, "rb") as fi:
		hmagic, hver = readpacked(fi, "<LH", True)
		assert hmagic == FILE_MAGIC
		assert hver == 1

		with open(filename_out, "wb") as fo:
			# https://www.tcpdump.org/manpages/pcap-savefile.5.html
			fo.write(struct.pack("<LHHLLLL", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 229))

			n = convert(fi, fo)

	print("Copied %d packets" % n)

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("Usage: bin2pcap.py <input .bin> <output .pcap>")
		exit(1)
	main(sys.argv[1], sys.argv[2])
	exit(0)
