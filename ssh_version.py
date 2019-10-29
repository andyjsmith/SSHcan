class SSHVersion:
	def __init__(self, version_number: str):
		self.version_number = version_number

	@property
	def major(self):
		ver_num = self.version_number

		# Remove the patch number if it exists
		if "p" in self.version_number:
			ver_num = ver_num.split("p")[0]

		if len(ver_num.split(".")) == 0:
			return None
		
		return int(ver_num.split(".")[0])

	@property
	def minor(self):
		ver_num = self.version_number

		# Remove the patch number if it exists
		if "p" in self.version_number:
			ver_num = ver_num.split("p")[0]

		if len(ver_num.split(".")) <= 1:
			return 0
		
		return int(ver_num.split(".")[1])

	@property
	def revision(self):
		ver_num = self.version_number

		# Remove the patch number if it exists
		if "p" in self.version_number:
			ver_num = ver_num.split("p")[0]

		if len(ver_num.split(".")) <= 2:
			return 0
		
		return int(ver_num.split(".")[2])

	@property
	def patch(self):
		if "p" not in self.version_number:
			return 0
		
		index = self.version_number.index("p")
		return int(self.version_number[index+1:])

	@property
	def version(self):
		return [self.major, self.minor, self.revision, self.patch]

	def __repr__(self):
		return "SSHVersion({}, {}, {}, {})".format(self.major, self.minor, self.revision, self.patch)

	def __str__(self):
		return str(self.version)

	def __lt__(self, other):
		for i in range(len(self.version)):
			if self.version[i] < other.version[i]:
				return True
			if self.version[i] > other.version[i]:
				return False
		return False
	
	def __gt__(self, other):
		for i in range(len(self.version)):
			if self.version[i] > other.version[i]:
				return True
			if self.version[i] < other.version[i]:
				return False
		return False

	def __eq__(self, other):
		for i in range(len(self.version)):
			if self.version[i] != other.version[i]:
				return False
		return True

	def __ne__(self, other):
		return not self.__eq__(other)

	def __le__(self, other):
		return not self.__gt__(other)

	def __ge__(self, other):
		return not self.__lt__(other)