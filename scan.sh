#!/bin/bash

iptables -A INPUT -p tcp --dport 61000 -j DROP
masscan 0.0.0.0/0 -p22 --banners --source-port 61000 --excludefile blacklist.txt --max-rate 100000 -oL out.txt