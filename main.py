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
import argparse
import progressbar
import geoip2.database

# Command line arguments
parser = argparse.ArgumentParser(description="SSHcan IPv4 address space scanner and statistics")
parser.add_argument("input_file", help="Masscan output file to read", type=str)
parser.add_argument("output_file", help="File to save JSON output", type=str)
parser.add_argument("--threads", help="Number of threads to use for parsing (x10 for IP resolution)", default=256, type=int)

args = parser.parse_args()

NUM_THREADS = args.threads

# Parse Masscan output file
print("Parsing Masscan output")
parser = SSHMasscanParser(args.input_file)
data = parser.parse()

# Resolve IP addresses
print("Resolving IP addresses")
host_resolver = SSHHostResolver(NUM_THREADS * 10, data)
data = host_resolver.run()

# Get location of IP addresses
print("Searching geoip database")
geoip = geoip2.database.Reader("GeoLite2-City.mmdb")
for host, props in data.items():
	location = geoip.city(host).location
	data[host]["lat"] = location.latitude
	data[host]["lon"] = location.longitude

# Get ciphers
print("Parsing SSH ciphers")
threaded_ciphers = SSHCiphersThreaded(NUM_THREADS, data)
data = threaded_ciphers.run()

# Get auth types
print("Getting auth types")
auth_types_parallel = SSHAuthTypes(NUM_THREADS, data)
data = auth_types_parallel.run()

# Parse banner
print("Parsing banners")
banner_progress = progressbar.ProgressBar(max_value=len(data))
banner_progress.update(0)
i = 0
for host, props in data.items():
	data[host]["parsed_banner"] = SSHBanner(props["banner"]).to_dict()
	i += 1
	if i % 1000 == 0: banner_progress.update(i)

banner_progress.finish()

# Get CVEs
print("Getting CVEs")
cve_progress = progressbar.ProgressBar(max_value=len(data))
cve_progress.update(0)
i = 0
sshcve = SSHCVE("SSH_CVE.csv")
for host, props in data.items():
	if props["parsed_banner"]["version"] is not None:
		data[host]["cve"] = sshcve.get_cve(SSHVersion(props["parsed_banner"]["version"]))
	i += 1
	if i % 100 == 0: cve_progress.update(i)

cve_progress.finish()

# Save to output file
json.dump(data, open(args.output_file, "w"))