
import requests
# import json
import ConfigParser
import os
import sys

# headers = {'Content-Type': 'application/json-rpc'}
# print auth
class Zhost:
	def __init__(self):
		self.id = 0
		self.name = ''
		self.status = 0
		# print self.commit(data)

# class


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
			print 'cannot get auth'
			print e
			sys.exit(1)

	def get_hostip(self):
		a_data = {'jsonrpc': "2.0", 'method': "hostinterface.get", 'params': {
			"output": "extend",
			"filter": {}
		}, 'auth': self.auth, 'id': self.times}

		# res = requests.post(self.z_url, json=a_data)
		res = self.commit(a_data)['result']
		# print res.json()
		for r in res:
			self.hosts.append(r['ip'])

	def del_host(self, ip):
		data = {
		}

	def get_host(self):
		data = {
			'jsonrpc': '2.0',
			'method':'host.get',
			'params':{
				'output': 'extend',
				'filter': {
					'host' : [
						'Linux server'
					]
				}
				# 'hostids': hostname,
			}
		}
		res = self.commit(data)
		print res


def main():
	Z = Zabbix()
	Z.get_auth()
	Z.get_host()
	# Z.get_hostip()
	# print Z.hosts


if __name__ == '__main__':
	main()
