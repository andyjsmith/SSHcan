from ssh_version import SSHVersion


class SSHBanner:
	def __init__(self, banner: str):
		self.banner = banner

	@property
	def version_string(self):
		return self.banner.split(" ")[0]

	@property
	def os_string(self):
		if len(self.banner.split(" ")) <= 1:
			return None

		return self.banner.split(" ")[1]

	@property
	def operating_system(self):
		if self.os_version == None:
			return None

		return self.os_string.split("-")[0]

	@property
	def version(self):
		index = self.version_string.index("-")
		index = self.version_string.index("-", index + 1)
		return self.version_string[index + 1:]

	@property
	def version_number(self):
		if not self.is_openssh:
			return None

		index = self.version.index("_")
		return self.version[index + 1:]

	@property
	def version_major(self):
		if not self.is_openssh:
			return None

		return SSHVersion(self.version_number).major

	@property
	def version_minor(self):
		if not self.is_openssh:
			return None

		return SSHVersion(self.version_number).minor

	@property
	def version_revision(self):
		if not self.is_openssh:
			return None

		return SSHVersion(self.version_number).revision

	@property
	def version_patch(self):
		if not self.is_openssh:
			return None

		return SSHVersion(self.version_number).patch

	@property
	def os_version(self):
		if self.os_string == None:
			return None

		return self.os_string.split("-")[1]

	@property
	def is_openssh(self):
		return "openssh" in self.version_string.lower()

	# SSH software, normally OpenSSH but also dropbear, Cisco, etc.
	@property
	def software(self):
		try:
			if "_" in self.version:
				return self.version[:self.version.rindex("_")].split("-")[0]
			else:
				return self.version.split("-")[0]
		except IndexError as err:
			return None

	# SSH version, normally 2.0
	@property
	def ssh_version(self):
		try:
			return self.version_string.split("-")[1]
		except IndexError as err:
			return None

	def to_dict(self):
		return {
			"version_string": self.version_string,
			"os_string": self.os_string,
			"operating_system": self.operating_system,
			"os_version": self.os_version,
			"ssh_version": self.ssh_version,
			"software": self.software,
			"version": self.version,
			"version_number": self.version_number,
			"version_major": self.version_major,
			"version_minor": self.version_minor,
			"version_revision": self.version_revision,
			"version_patch": self.version_patch,
			"is_openssh": self.is_openssh
		}

	def __str__(self):
		return self.banner
