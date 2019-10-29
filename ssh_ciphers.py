import socket
from ssh_algorithms import Algorithms

class SSHCiphers:
	def __init__(self, ip_address: str, port: int):
		self.ip_address = ip_address
		self.port = port
		self.__connect()
		self.__parse_ciphers()
		
	def __connect(self):
		conn = socket.create_connection((self.ip_address, self.port),5)
		banner = conn.recv(50).split(b'\n')[0]
		conn.send(b'SSH-2.0-OpenSSH_7.9p1\r\n')
		ciphers = conn.recv(2048)
		conn.close()
		self.raw_ciphers = ciphers.split(b"\x00\x00\x00\x15")[0].decode("latin1")
		self.raw_banner = banner

	def __parse_ciphers(self):
		self.weak_ciphers = []
		self.weak_macs = []
		self.weak_kex = []
		self.weak_hka = []
		
		# Message authentication code algorithms
		self.macs = []
		for alg in Algorithms.ALGORITHMS["mac"].keys():
			if alg in self.raw_ciphers:
				self.macs.append(alg)
				if len(Algorithms.ALGORITHMS["mac"][alg]) != 0:
					self.weak_macs.append(alg)
		
		# Ciphers
		self.ciphers = []
		for alg in Algorithms.ALGORITHMS["enc"].keys():
			if alg in self.raw_ciphers:
				self.ciphers.append(alg)
				if len(Algorithms.ALGORITHMS["enc"][alg]) != 0:
					self.weak_ciphers.append(alg)
		
		# Key exchange algorithms
		self.kex = []
		for alg in Algorithms.ALGORITHMS["kex"].keys():
			if alg in self.raw_ciphers:
				self.kex.append(alg)
				if len(Algorithms.ALGORITHMS["kex"][alg]) != 0:
					self.weak_kex.append(alg)
		
		# Host key algorithms
		self.hka = []
		for alg in Algorithms.ALGORITHMS["key"].keys():
			if alg in self.raw_ciphers:
				self.hka.append(alg)
				if len(Algorithms.ALGORITHMS["key"][alg]) != 0:
					self.weak_hka.append(alg)

	def to_dict(self):
		return {
			"kex": self.kex,
			"weak_kex": self.weak_kex,
			"macs": self.macs,
			"weak_macs": self.weak_macs,
			"hka": self.hka,
			"weak_hka": self.weak_hka,
			"ciphers": self.ciphers,
			"weak_ciphers": self.weak_ciphers
		}