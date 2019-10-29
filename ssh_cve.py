from ssh_version import SSHVersion
import csv

class SSHCVE:
	def __init__(self, csvpath: str):
		self.raw_cve_data = []
		self.cve_data = []
		with open(csvpath, mode='r') as csv_file:
			csv_reader = csv.DictReader(csv_file)
			line_count = 0
			for row in csv_reader:
				self.raw_cve_data.append(row)

		# Parse each row for the major, minor, revision, patch
		self.cve_data = self.raw_cve_data
		for i in range(len(self.cve_data)):
			self.cve_data[i]["earliest_version"] = SSHVersion(self.cve_data[i]["earliest_version"])
			self.cve_data[i]["latest_version"] = SSHVersion(self.cve_data[i]["latest_version"])

	def get_cve(self, version: SSHVersion, min_score=0):
		cves = []
		for cve in self.cve_data:
			if cve["latest_version"] >= version and cve["earliest_version"] <= version and float(cve["score"] >= min_score):
				cves.append(cve["cve"])
		
		return cves

# SSHCVE("SSH_CVE.csv")