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
		self.z_url = 'https://zabbix.zhai.me/api_jsonrpc.php'
		self.times = 1
		self.hosts = []

	def commit(self, data):
		res = requests.post(self.z_url, json=data).json()
		self.times += 1
		return res

	def get_auth(self):
		try:
			config = ConfigParser.ConfigParser()
			config.read(os.path.expanduser('~/zabbix.cfg'))
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
	h = Z.get_host_by_name('wiki')
	print h
	# Z.get_host_by_name('wiki2')


if __name__ == '__main__':
	main()
