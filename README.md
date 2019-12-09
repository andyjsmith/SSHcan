# SSHcan
Scans the entire IPv4 address space for SSH statistics and misconfiguration. Final Project for CYSE 330 at GMU.

## Requirements
* Linux-based OS with iptables
* Masscan
* Python 3
* PIP 3
* PIP dependencies (`pip3 install -r requirements.txt`)
* Custom fork of the Paramiko library (automatically installed with the above command)
* GeoLite2-City database saved to this directory. Available from https://dev.maxmind.com/geoip/geoip2/geolite2/

## Running
* Run the `scan.sh` script as root to run the masscan program.
* Run the processing scripts: `python3 main.py <input_file> <output_file>` (e.g. `python3 main.py masscan_output.txt sshcan_output.json`)
* Perform data processing on the output file