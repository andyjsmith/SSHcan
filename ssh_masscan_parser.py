class SSHMasscanParser:
	def __init__(self, filename):
		self.filename = filename
		self.data = dict()

	def parse(self):
		with open(self.filename, "r") as fp:
			for line in fp:
				# Only parse banner lines
				if not line.startswith("banner"):
					continue

				cols = line.split(" ")

				# Only include SSH banner responses (connection refused; Microsoft FTP)
				if cols[5].lower() != "ssh":
					continue

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
