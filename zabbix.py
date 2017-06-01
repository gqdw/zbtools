import requests
import json
import ConfigParser
import os
import sys


# headers = {'Content-Type': 'application/json-rpc'}

# print auth
class HostInterface:
	def __init__(self):
		ip = None
		hostid = None
		port = None
		interfaceid = None
	def __repr__(self):
		return 'HostInterface: interfaceid-> %s \t hostid -> %s \t ip-> %s \t port-> %s \n' % (self.interfaceid ,self.hostid , self.ip , self.port )


class Host:
	def __init__(self):
		hostid = None
		available = 0
		host = None
		status = 0

	def __repr__(self):
		return 'Host: host -> %s \t hostid -> %s \t available -> %s \t status -> %s \n' \
			% (self.host, self.hostid, self.available, self.status)

class Zabbix:
	def __init__(self):
		self.auth = ''
		self.z_url = ''
		self.times = 1
		self.hosts = []

	def commit(self, data):
		res = requests.post(self.z_url, json=data,auth=('admin', 'eastmoney2017')).json()
		self.times += 1
		return res

	def get_auth(self):
		try:
			config = ConfigParser.ConfigParser()
			config.read(os.path.expanduser('~/zabbix.cfg'))
			url = config.get('main', 'url')
			self.z_url = url
			user = config.get('main', 'user')
			password = config.get('main', 'password')
			a_data = {"jsonrpc": "2.0", "method": "user.login", "params": {"user": user, "password": password}, "id": 1}
			# self.auth = requests.post(self.z_url, json=a_data).json()['result']
			self.auth = self.commit(a_data)['result']
		except Exception as e:
			print 'cannot read password from ~/zabbix.cfg'
			sys.exit(1)

	def del_host_from_ip(self, ip):
		hostid = None
		for h in self.hosts:
			if ip == h.ip:
				hostid = h.hostid
		data = {
		    "jsonrpc": "2.0",
		    "method": "host.delete",
		    "params": [
		        hostid
		    ],
		    "auth": self.auth,
		    "id": self.times
		}
		print data
		if hostid != None:
			res = self.commit(data)
			print res
			print 'host %s deleted!' % ip

	def get_group(self):
		data = {
    "jsonrpc": "2.0",
    "method": "hostgroup.get",
    "params": {
        "output": "extend",
        "filter": {
            "name": [
                "zp-nuff",
                "Linux servers"
            ]
        }
    },
    "auth": self.auth,
    "id": self.times
}
		res = self.commit(data)
		print res;


		

	def get_hostip(self):
		a_data = {
			"jsonrpc": "2.0",
			"method": "hostinterface.get",
			"params": {
				"output": "extend",
				"filter": {}
			},
			"auth": self.auth,
			"id": self.times
		}
		# res = requests.post(self.z_url, json=a_data)
		res = self.commit(a_data)['result']
		# print res.json()
		for r in res:
			# print r
			host = HostInterface();
			host.ip = r['ip']
			host.hostid = r['hostid']
			host.port = r['port']
			host.interfaceid = r['interfaceid']
			# self.hosts.append(r['ip'])
			self.hosts.append(host)

	def add_host(self, name, ip):
		data = {
    "jsonrpc": "2.0",
    "method": "host.create",
    "params": {
        "host": name,
        "interfaces": [
            {
                "type": 1,
                "main": 1,
                "useip": 1,
                "ip": ip,
                "dns": "",
                "port": "20050"
            }
        ],
        "groups": [
            {
                "groupid": "39"
            }
        ],
		"proxy_hostid" : "11409",
        "inventory_mode": 0,
    },
    "auth": self.auth,
    "id": self.times
	}
		res = self.commit(data)
		print res

	def get_proxy(self):
		data = {
    "jsonrpc": "2.0",
    "method": "proxy.get",
    "params": {
        "output": "extend",
        "selectInterface": "extend"
    },
    "auth": self.auth,
    "id": self.times
}
		res = self.commit(data)

		print json.dumps(res,sort_keys=True,indent=4)

	def get_host_by_name(self, hostname):
		'''
		return Host Object
		'''
		data = {
		    "jsonrpc": "2.0",
		    "method": "host.get",
		    "params": {
		        "output": "extend",
		        "filter": {
		            "host": [
		                hostname,
		            ]
		        }
		    },
		    "auth": self.auth,
		    "id": self.times
		}
		res = self.commit(data)
		try:
			host = res.get('result')[0]
			# for debug
			print host
			h = Host()
			h.available = host.get('available')
			h.status = host.get('status')
			h.host = host.get('host')
			h.hostid = host.get('hostid')
			return h
			# h
		except Exception as e:
			print 'cannot get host by the name'
			sys.exit(2)
		# host = res['result'][0]

def main():
	Z = Zabbix()
	Z.get_auth()
	Z.get_hostip()
	# print Z.hosts
	# ip = '10.45.51.80'
	# Z.del_host_from_ip(ip)
	h = Z.get_host_by_name('218.244.148.60')
	print h
	# push group id : 58
	Z.get_group()
	# Z.get_host_by_name('wiki2')
	# get proxy id ZP :  11409
	# Z.get_proxy()
	# Z.add_host('10.205.102.121', '10.205.102.121')
	# f = open('hosts.txt')

	# f = open('nuff.txt')
	f = open('add-hosts.txt')
	# f = open('nuff-ems.txt')
#	for line in f:
#		h = line.strip()
#		try:
#			Z.add_host('nuff-'+h,h)
#		except Exception as e:
#			print 'cannot create host: ',h


if __name__ == '__main__':
	main()
