#!/usr/bin/env python3

'''

Compares returned SUID binaries with list of exploitable binaries pulled from GTFOBins.
Also looks for SUID Binaries outside of the /usr/, /opt/, and /bin/ directories.

Usage:

./initialSUID.py

'''

import sys, os, random

gtfobins = ['ar', 'aria2c', 'arj', 'arp', 'as', 'ash', 'atobm', 'awk', 'base32', 'base64', 'basenc', 'bash', 'bridge', 'busybox', 'byebug', 'bzip2', 'capsh', 'cat', 'chmod', 'chown', 'chroot', 'cmp', 'column', 'comm', 'composer', 'cp', 'cpio', 'cpulimit', 'csh', 'csplit', 'csvtool', 'cupsfilter', 'curl', 'cut', 'dash', 'date', 'dd', 'dialog', 'diff', 'dig', 'dmsetup', 'docker', 'dosbox', 'dvips', 'ed', 'emacs', 'env', 'eqn', 'expand', 'expect', 'file', 'find', 'flock', 'fmt', 'fold', 'gawk', 'gcore', 'gdb', 'gimp', 'git', 'grep', 'gtester', 'gzip', 'hd', 'head', 'hexdump', 'highlight', 'hping3', 'iconv', 'iftop', 'install', 'ionice', 'ip', 'jjs', 'join', 'jq', 'jrunscript', 'ksh', 'ksshell', 'latex', 'ld.so', 'ldconfig', 'less', 'logsave', 'look', 'lua', 'lualatex', 'luatex', 'make', 'mawk', 'more', 'msgattrib', 'msgcat', 'msgconv', 'msgfilter', 'msgmerge', 'msguniq', 'mv', 'mysql', 'nano', 'nasm', 'nawk', 'nc', 'nice', 'nl', 'nmap', 'node', 'nohup', 'octave', 'od', 'openssl', 'openvpn', 'paste', 'pdflatex', 'pdftex', 'perf', 'perl', 'pg', 'php', 'pic', 'pico', 'pr', 'pry', 'python', 'rake', 'readelf', 'restic', 'rev', 'rlwrap', 'rpm', 'rpmquery', 'rsync', 'run-parts', 'rview', 'rvim', 'scp', 'sed', 'setarch', 'shuf', 'slsh', 'socat', 'soelim', 'sort', 'sqlite3', 'ss', 'ssh-keygen', 'ssh-keyscan', 'start-stop-daemon', 'stdbuf', 'strace', 'strings', 'sysctl', 'systemctl', 'tac', 'tail', 'tar', 'taskset', 'tbl', 'tclsh', 'tee', 'telnet', 'tex', 'tftp', 'tic', 'time', 'timeout', 'troff', 'ul', 'unexpand', 'uniq', 'unshare', 'update-alternatives', 'uudecode', 'uuencode', 'view', 'vigr', 'vim', 'vimdiff', 'vipw', 'watch', 'wc', 'wget', 'whiptail', 'xargs', 'xelatex', 'xetex', 'xmodmap', 'xmore', 'xxd', 'xz', 'zip', 'zsh', 'zsoelim']

def main():
	found = 0
	randnum = random.randint(1000, 9999)
	outfile = "/tmp/IS{}.tmp".format(str(randnum))
	command = r"find / -type f -perm -u=s -exec ls -ldb {} \; 2>/dev/null >> " + outfile

	os.system(command)

	with open(outfile) as f:
		scan = f.readlines()

		pathName = ''
		binName = ''
		workingLine = []


		for line in scan:
			workingLine = line.split(' ')
			pathName = workingLine[-1].strip()
			workingLine = line.split('/')
			binName = workingLine[-1].strip()
			if binName in gtfobins:
				print("Possible vulnerable SUID found: {}".format(pathName))
				print("Check https://gtfobins.github.io/gtfobins/{}/ for details".format(binName))
				print("")
				found += 1
				break

			if not pathName.startswith("/usr/"):
				if not pathName.startswith("/opt/"):
					if not pathName.startswith("/bin/"):
						print('Binary found outside of usual Linux directories: {}'.format(pathName))
						print('Recommend researching')
						print('')
						found +=1


	if os.path.exists(outfile):
		os.remove(outfile)

	print("{} potentially vulnerable binaries have been found.".format(found))


if __name__ == "__main__":
   main()
