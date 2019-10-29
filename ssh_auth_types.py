import paramiko
import socket
import threading
import queue
import logging
from enum import Enum

class SSHError(Enum):
	SUCCESS = 0
	CONNECTION_REFUSED = 1
	CONNECTION_TIMEOUT = 2
	GAIERROR = 3
	INVALID_BANNER = 4

# Possible types: ['publickey', 'password', 'keyboard-interactive', 'hostbased', 'gssapi-keyex', 'gssapi-with-mic']
# also gssapi?

class SSHAuthTypes:

	# Don't log exceptions from Paramiko transport threads, already handled in worker
	logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

	def __init__(self, num_threads: int, data: dict):
		self.num_threads = num_threads
		self.data = data
		self.threads = []
		self.q = queue.Queue()

		for host, props in data.items():
			self.q.put_nowait((host, props["port"]))

	def run(self):
		for i in range(self.num_threads):
			t = threading.Thread(target=self.__ssh_worker)
			t.start()
			self.threads.append(t)

		# Block until all queue tasks are done
		self.q.join()

		# Stop workers
		for i in range(self.num_threads):
			self.q.put(None)
		for t in self.threads:
			t.join()

		return self.data

	def __ssh_worker(self):
		while True:
			host = self.q.get()
			if host is None:
				break
			s = socket.socket()
			s.settimeout(1.0)

			# Connect over TCP socket
			try:
				s.connect(host)
			except socket.timeout as err:
				self.data[host[0]]["auth_types"] = SSHError.CONNECTION_TIMEOUT
				self.q.task_done()
				continue
			except socket.gaierror as err:
				self.data[host[0]]["auth_types"] = SSHError.GAIERROR
				self.q.task_done()
				continue
			except ConnectionRefusedError as err:
				self.data[host[0]]["auth_types"] = SSHError.CONNECTION_REFUSED
				self.q.task_done()
				continue
			
			# Connect with SSH over socket
			try:
				t = paramiko.Transport(s)
				t.connect()
			except (paramiko.ssh_exception.SSHException, EOFError) as err:
				self.data[host[0]]["auth_types"] = SSHError.INVALID_BANNER
				self.q.task_done()
				continue

			# Try authentication to get allowed SSH auth types
			try:
				t.auth_none('')
			except paramiko.BadAuthenticationType as err:
				self.data[host[0]]["auth_types"] = err.allowed_types
			
			self.q.task_done()