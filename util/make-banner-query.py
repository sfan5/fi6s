#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
import sys
import struct

###############################################################################

# This handshake claims support for (EC-)DHE + AES-128 or AES-256 + CBC
# or GCM mode, and SHA256 or SHA1 for signatures, as well as some extensions
# expected by modern server implementations. So it should work with both modern
# and older server configs.
def tls():
	def extension(id_, data):
		return struct.pack("!H", id_) + data
	def supported_groups(groups):
		gx = b"".join(struct.pack("!H", val) for val in groups)
		return extension(10, struct.pack("!HH", len(gx) + 2, len(gx)) + gx)
	def signature_algorithms(algs):
		ax = b"".join(struct.pack("!H", val) for val in algs)
		return extension(13, struct.pack("!HH", len(ax) + 2, len(ax)) + ax)
	def record(type_, version, data):
		return struct.pack("!BHH", type_, version, len(data)) + data

	suites = [
		0xc02b, 0xc02c, 0xc009, 0xc00a, # ECDHE+ECDSA
		0xc02f, 0xc030, 0xc013, 0xc014, # ECDHE+RSA
		0x9e, 0x9f, 0x33, 0x39, # DHE+RSA
	]
	sx = b"".join(struct.pack("!H", val) for val in suites)

	exts = b"".join([
		extension(0xff01, b"\x00\x01\x00"), # renegotiation_info
		supported_groups([0x0019, 0x0017]),
		extension(11, b"\x00\x02\x01" b"\x00"), # ec_point_formats
		signature_algorithms([0x0401, 0x0201, 0x0403, 0x0603]),
		extension(23, b"\x00\x00"), # extended_master_secret
	])

	parts = [
		b"\x01", # Client Hello (1)
		b"xxx", # Length
		b"\x03\x03" # TLS 1.2
		# Random
		b"\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa"
		b"\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa"
		b"\x00", # Session ID length
		struct.pack("!H", len(sx)), sx, # Cipher Suites
		b"\x01\x00", # Null Compression
		struct.pack("!H", len(exts)), exts, # Extensions
	]
	hlen = sum(len(b) for b in parts)
	parts[1] = struct.pack("!L", hlen - 4)[1:]

	# Handshake (22)
	# Version: TLS 1.0
	return record(22, 0x0301, b"".join(parts))

###############################################################################

if __name__ == "__main__":
	b = locals()[sys.argv[1]]()
	q = 12
	for i in range(999):
		b2 = b[q*i:q*i+q]
		if not b2:
			break
		s = "".join("\\x%02x" % n for n in b2)
		print("\t\t\"%s\"" % s)
