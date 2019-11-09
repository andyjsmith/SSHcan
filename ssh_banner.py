import re
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
		
		return "".join(self.banner.split(" ")[1:])

	# Operating system name (e.g. Ubuntu, Debian, etc.)
	@property
	def operating_system(self):
		if self.os_version == None:
			return None

		if not self.is_openssh:
			return None

		return self.os_string.split("-")[0]

	# Operating system version number
	@property
	def os_version(self):
		if self.os_string == None:
			return None

		if not self.is_openssh:
			return None
		
		if "-" not in self.os_string:
			return None

		# Parse Debian OS version
		if "debian" in self.os_string.lower() or "raspbian" in self.os_string.lower():
			match = re.search(r'\d+', self.os_string.split("-")[1])
			if match is not None: return match.group()
		
		return self.os_string.split("-")[1]

	@property
	def version(self):
		index = self.version_string.index("-")
		
		if "-" in self.version_string[index + 1:]:
			index = self.version_string.index("-", index + 1)
		
		return self.version_string[index + 1:]

	@property
	def version_number(self):
		if not self.is_openssh:
			return None

		if "_" not in self.version:
			return None

		index = self.version.index("_")
		return self.version[index + 1:]

	@property
	def version_parsed(self):
		if self.version_number is None:
			return None
		return SSHVersion(self.version_number).version

	@property
	def is_openssh(self):
		return "openssh" in self.version_string.lower()

	# SSH software, normally OpenSSH but also dropbear, Cisco, etc.
	@property
	def software(self):
		software_string = self.banner.lower()
		if "openssh" in software_string: return "OpenSSH"
		if "weonlydo" in software_string: return "WeOnlyDo"
		if "cpx" in software_string: return "CPX"
		if "dropbear" in software_string: return "Dropbear"
		if "cisco" in software_string: return "Cisco"
		if "flowssh" in software_string: return "FlowSsh"
		if "zxyel" in software_string: return "Zyxel"
		if "mocana" in software_string: return "Mocana"
		if "fortressssh" in software_string: return "FortressSSH"
		if "globalscape" in software_string: return "GlobalScape"
		if "ip*works" in software_string: return "IP*Works!"
		if "obs sftp" in software_string: return "OBS"
		if "cerberus" in software_string: return "Cerberus"
		if "cleo harmony" in software_string: return "Cleo Harmony"
		if "cleo vlproxy" in software_string: return "Cleo VLProxy"
		if "openvms" in software_string: return "OpenVMS"
		if "psftpd" in software_string: return "PSFTPd"
		if "vshell" in software_string: return "VShell"
		if "xfb.gateway" in software_string: return "Axway XFB"
		if "intel" in software_string: return "Intel"
		if "warwick" in software_string: return "Warwick J2SSH"
		if "any.work" in software_string: return "any.work"
		if "sshlib" in software_string: return "SSHLib"

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
			"version_string": self.version_number,
			"os_string": self.os_string,
			"operating_system": self.operating_system,
			"os_version": self.os_version,
			"ssh_version": self.ssh_version,
			"software": self.software,
			"version": self.version_parsed,
			"is_openssh": self.is_openssh
		}

	def __str__(self):
		return self.banner
