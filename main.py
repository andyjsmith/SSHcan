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
import gzip
import sys
import argparse

# Command line arguments
parser = argparse.ArgumentParser(description="SSHcan IPv4 address space scanner and statistics")
parser.add_argument("masscan_output", help="Masscan output file to read", type=str)
parser.add_argument("--threads", help="Number of threads to use for parsing (x200 for IP resolution)", default=8, type=int)

args = parser.parse_args()

NUM_THREADS = args.threads

# Parse Masscan output file
print("Parsing Masscan output")
parser = SSHMasscanParser(args.masscan_output)
data = parser.parse()

# Resolve IP addresses
print("Resolving IP addresses")
host_resolver = SSHHostResolver(NUM_THREADS * 200, data)
data = host_resolver.run()

# Parse SSH ciphers
print("Parsing SSH ciphers")
threaded_ciphers = SSHCiphersThreaded(NUM_THREADS, data)
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
auth_types_parallel = SSHAuthTypes(NUM_THREADS, data)
data = auth_types_parallel.run()

# print(json.dumps(data))

compressed_data = gzip.compress(json.dumps(data).encode("utf-8"))
print(compressed_data)