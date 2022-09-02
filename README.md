# parser

Parse Snort IDS rules and generate packets using Scapy to trigger Snort alerts

## Goal

This project is the first of three which will build upon one another:

- Generate Traffic from IDS rules
- Generate Traffic with threat profile
- Generate responsive tool

Parser will parse Snort IDS rules and generate traffic in order to determine if deceptive traffic can be tailored to trip Snort and similar misuse detection systems rules to create alerts. Deceptive traffic will be created by modifying request payloads.

## Example

Exchange Hafnium
- Craft packets to trigger Hafnium exploit attempt alerts
- Craft packets to trigger C2 related alerts
- Can defenders detect incoming requests and C2 events via Snort

Solarwinds Sunburst
- Craft packets to trigger Sunburst related C2 communcation alerts
- Can defender detect incoming/outgoing C2 beacons via Snort

Log4j
- Craft packets that would trigger Log4j exploit attempt alerts
- Can defenders detect exploitation attempts via Snort

## Example Rules 

See [snort-rules](snort-rules)

Talos summaries below:

- [Hafnium](https://blog.talosintelligence.com/2021/03/threat-advisory-hafnium-and-microsoft.html)
- [Sunburst - Solarwinds](https://blog.talosintelligence.com/2020/12/solarwinds-supplychain-coverage.html)
- [Log4j](https://blog.talosintelligence.com/2021/12/apache-log4j-rce-vulnerability.html)

## Requirements

**Aberdeen specific requirements**

Tested on Ubuntu 20.04.4 on VMware Fusion

- Install and update Ubuntu
`sudo apt update && sudo apt upgrade`

- Ubuntu has Python 3.8 installed by default. Aberdeen supports 3.9 and newer so we need to install a newer version of Python.
```
sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev -y
wget https://www.python.org/ftp/python/3.9.12/Python-3.9.12.tgz
tar xzf Python-3.9.12.tgz
cd Python-3.9.12/
./configure --enable-optimizations
make
sudo make altinstall
```

- Create and enter a virtual environment
```
cd
python3.9 -m venv venv
. venv/bin/activate
```

Clone and install Aberdeen. Without Snort 3 installed, `pytest` will have errors.
```
git clone https://gitlab.com/rsreese/aberdeen.git
cd aberdeen
python setup.py pytest
python setup.py install
```

To test Aberdeen at its currently capability, create file name `test.rules` with
```
alert tcp 172.16.255.100 any -> 172.16.255.101 443 (msg:"443 incoming"; sid:1000001)
alert tcp 172.16.253.105 any -> 172.16.252.107 [22,23] (msg:"ssh/telnet incoming"; sid:1000002)
alert tcp 172.16.255.101 any -> 172.16.255.102 [80:443] (msg:"between 80-443 incoming"; sid:1000003)
```
and run the following which will generate errors without Snort installed but will generate PCAP for the above rules. Since Snort is not installed, it will generate a file six packets, three benign and three which will cause Snort to create alerts.
```
aberdeen test.file
```

**Snort specific requirements**

The following is a minimal Snort deployment, a more exhaustive deployment example can be found at https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/011/074/original/Snort_3_on_Ubuntu_18_and_20.pdf but is not necessary for using Aberdeen.

Install the following dependencies
```
sudo apt install -y build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev libpcap-dev \
zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev openssl libssl-dev cpputest libsqlite3-dev \
libtool uuid-dev git autoconf bison flex libcmocka-dev libnetfilter-queue-dev libunwind-dev \
libmnl-dev ethtool libpcre3-dev
```
Install DAQ
```
wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.6.tar.gz
tar xzf v3.0.6.tar.gz
cd libdaq-3.0.6
./bootstrap
./configure
make
sudo make install
sudo ldconfig
```
Install Snort
```
wget https://github.com/snort3/snort3/archive/refs/tags/3.1.27.0.tar.gz
tar xzf 3.1.27.0.tar.gz
cd snort3-3.1.27.0/
ls
./configure_cmake.sh --prefix=/usr/local
cd build/
sudo make -j $(nproc) install
```
Test Snort with a command such as
```
snort -c snort3-3.1.27.0/lua/snort.lua -r test_packets.1649897414.pcap -R test.rules -A alert_full -L log_pcap -s 65535
```
