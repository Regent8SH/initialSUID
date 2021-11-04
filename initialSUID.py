#!/usr/bin/env python3

'''

Removes any exteremly common SUID binaries from the SUID search. Will update as necessary.

Usage:

./quickSUID.py

'''

import sys, os

std = ["chsh", "sudo", "newgrp", "ntfs", "kismet", "fusermount3", "vmware", "chfn", "passwd", "su", "pkexec", "gpasswd", "mount", "umount", "pppd"]

outfile = "/tmp/qsuid.tmp"

def main():
	os.system(r"find / -type f -perm -u=s -exec ls -ldb {} \; 2>/dev/null >> /tmp/qsuid.tmp")

	with open(outfile) as f:
		scan = f.readlines()

		for line in scan:
			if not any(binary in line for binary in std):
				print(line)

	if os.path.exists(outfile):
		os.remove(outfile)


if __name__ == "__main__":
   main()
