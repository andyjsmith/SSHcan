class SSHMasscanParser:
	def __init__(self, filename):
		self.filename = filename
		self.data = dict()

	def parse(self):
		with open(self.filename, "r") as fp:
			for line in fp:
				if not line.startswith("banner"):
					continue

				cols = line.split(" ")

				self.data[cols[3]] = {
					"port": int(cols[2]),
					"banner": " ".join(cols[6:]).strip(),
					"parsed_banner": None,
					"ciphers": None,
					"auth_types": None,
					"hostname": None,
					"cve": None
				}

		return self.data

# Sample -oL outputs
# theoretically only need parse banner responses, don't care about the "open" rows

# port state, protocol, port number, ip address, posix timestamp