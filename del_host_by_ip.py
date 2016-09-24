#!/usr/bin/env python
from zabbix import Zabbix
import sys

def main():
	if len(sys.argv) != 2:
		print 'useage: %s [the-host-ip]' % (sys.argv[0])
		sys.exit(1)
	Z = Zabbix()
	Z.get_auth()
	Z.get_hostip()
	ip = sys.argv[1]
	Z.del_host_from_ip(ip)


if __name__ == '__main__':
	main()
