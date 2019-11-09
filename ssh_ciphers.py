import socket
from ssh_algorithms import Algorithms

class SSHCiphers:
	def __init__(self, ip_address: str, port: int):
		self.ip_address = ip_address
		self.port = port
		
		self.weak_ciphers = []
		self.weak_macs = []
		self.weak_kex = []
		self.weak_hka = []
		self.ciphers = []
		self.macs = []
		self.kex = []
		self.hka = []

		self.__connect()
		self.__parse_ciphers()
		
	def __connect(self):
		self.raw_ciphers = None
		self.raw_banner = None

		try:
			conn = socket.create_connection((self.ip_address, self.port),5)
		except (ConnectionRefusedError, ConnectionResetError) as err:
			return

		conn.settimeout(2.0)

		try:
			banner = conn.recv(50).split(b'\n')[0]
			conn.send(b'SSH-2.0-OpenSSH_7.9p1\r\n')
			ciphers = conn.recv(2048)
		except ConnectionResetError as err:
			conn.close()
			return
		
		conn.close()
		self.raw_ciphers = ciphers.split(b"\x00\x00\x00\x15")[0].decode("latin1")
		self.raw_banner = banner

	def __parse_ciphers(self):
		# Skip parse if connection was unsuccessful
		if self.raw_ciphers == None or self.raw_banner == None: return
		
		# Message authentication code algorithms
		for alg in Algorithms.ALGORITHMS["mac"].keys():
			if alg in self.raw_ciphers:
				self.macs.append(alg)
				if len(Algorithms.ALGORITHMS["mac"][alg]) != 0:
					self.weak_macs.append(alg)
		
		# Ciphers
		for alg in Algorithms.ALGORITHMS["enc"].keys():
			if alg in self.raw_ciphers:
				self.ciphers.append(alg)
				if len(Algorithms.ALGORITHMS["enc"][alg]) != 0:
					self.weak_ciphers.append(alg)
		
		# Key exchange algorithms
		for alg in Algorithms.ALGORITHMS["kex"].keys():
			if alg in self.raw_ciphers:
				self.kex.append(alg)
				if len(Algorithms.ALGORITHMS["kex"][alg]) != 0:
					self.weak_kex.append(alg)
		
		# Host key algorithms
		for alg in Algorithms.ALGORITHMS["key"].keys():
			if alg in self.raw_ciphers:
				self.hka.append(alg)
				if len(Algorithms.ALGORITHMS["key"][alg]) != 0:
					self.weak_hka.append(alg)

	def to_dict(self):
		return {
			"weak_kex": self.weak_kex,
			"weak_macs": self.weak_macs,
			"weak_hka": self.weak_hka,
			"weak_ciphers": self.weak_ciphers
		}