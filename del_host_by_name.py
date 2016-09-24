#!/usr/bin/env python
from zabbix import Zabbix,Host
import sys

def main():
	if len(sys.argv) != 2:
		print 'useage: %s [the-host-name]' % (sys.argv[0])
		sys.exit(1)
	Z = Zabbix()
	Z.get_auth()
	Z.get_hostip()
	# print Z.hosts
	hostname = sys.argv[1]

	h = Z.get_host_by_name(hostname)
	print h
	# print h.hostid
	ip = None
	for hi in Z.hosts:
		if hi.hostid == h.hostid:
			ip = hi.ip
			# print ip
	
	if ip == None:
		print 'something wrong,exiting...'
		sys.exit(1)
	else:
		Z.del_host_from_ip(ip)


if __name__ == '__main__':
	main()
