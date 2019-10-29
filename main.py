from ssh_banner import SSHBanner
from ssh_ciphers import SSHCiphers
from ssh_masscan_parser import SSHMasscanParser
from ssh_auth_types import SSHAuthTypes
from ssh_cve import SSHCVE
from ssh_version import SSHVersion
from ssh_host_resolver import SSHHostResolver
from ssh_ciphers_threaded import SSHCiphersThreaded
import json
import socket
import sys

parser = SSHMasscanParser("masscanoutput.txt")
data = parser.parse()

# Resolve IP addresses
print("Resolving IP addresses")
host_resolver = SSHHostResolver(5, data)
data = host_resolver.run()

# Parse SSH ciphers
print("Parsing SSH ciphers")
threaded_ciphers = SSHCiphersThreaded(5, data)
data = threaded_ciphers.run()

# Parse SSH banner
print("Parsing SSH banner")
for host, props in data.items():
	data[host]["parsed_banner"] = SSHBanner(props["banner"]).to_dict()

# Get CVEs
print("Getting CVEs")
for host, props in data.items():
	data[host]["cve"] = SSHCVE("SSH_CVE.csv").get_cve(SSHVersion(props["parsed_banner"]["version_number"]))

# Get auth types
print("Getting auth types")
auth_types_parallel = SSHAuthTypes(5, data)
data = auth_types_parallel.run()

print(json.dumps(data))