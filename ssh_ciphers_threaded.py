from ssh_ciphers import SSHCiphers
import threading
import queue
import socket

class SSHCiphersThreaded:
	def __init__(self, num_threads: int, data: dict):
		self.num_threads = num_threads
		self.data = data
		self.threads = []
		self.q = queue.Queue()

		for host, props in data.items():
			self.q.put_nowait((host, props["port"]))

	def run(self):
		for i in range(self.num_threads):
			t = threading.Thread(target=self.__resolver_worker)
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

	def __resolver_worker(self):
		while True:
			host = self.q.get()
			if host is None:
				break
			
			try:
				ciphers = SSHCiphers(host[0], host[1]).to_dict()
			except socket.timeout as err:
				ciphers = "ERROR"
			
			self.data[host[0]]["ciphers"] = ciphers
			
			self.q.task_done()