# SApp(Small Application) Network Tool

#### Video Demo:  https://youtu.be/yYhk0Vn2VNQ

#### Description:
SApp or Simple Application Network Tool is a Python script that provides network-related functionalities such as PingSweep, Traceroute, NSlookup, and Check IP Overlaps. This tool allows users to perform basic network diagnostics and obtain information about IP addresses, hostnames, routing paths, and potential ip conflicts due to overlapping ip address subnets.

## Table of Contents

- [Features](#features)
- [Usage](#usage)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Contributing](#contributing)

## Features

1. **PingSweep**: Conducts a ping sweep on a specified IP range and displays information about the reachability status and latency of each host.
2. **Traceroute**: Traces the route that packets take to reach a specified destination IP address and provides information about each hop, including round-trip times (RTT) and next-hop routers.
3. **NSlookup**: Performs a DNS lookup for a given hostname, providing information about resolved IP addresses and status.
4. **Check IP Overlaps**: This feature of ipaddress module revalidates if ipv4 addresses either single host to a range of subnets will determine whether or not both network 1 and network 2 have potential overlapping issue.

## Usage

1. **PingSweep**: Enter `1` to initiate a PingSweep. Provide the target IP range in CIDR notation (e.g., 192.168.1.0/24).
2. **Traceroute**: Enter `2` to perform a Traceroute. Input the destination IP address and specify the number of hops (default number of hops is 12).
3. **NSlookup**: Enter `3` to perform an nslookup. Input the hostname to look up (e.g. iana.org).
4. **Check IP Overlaps**: Enter `4` to access Check IP Overlaps. Input multiple ipv4 addresses or subnets for revalidating potential overlapping issue. Use can input either single host(e.g. 192.168.0.1) or ip subnet range(e.g. 192.168.0.0/24). It will tell then the user if the networks being validated are either "Overlaps" or "Unique".
5. **Quit**: Enter `5` to exit the SApp Network Tool.

## Dependencies

The script relies on the following Python modules:

- `ipaddress`: Used for the PingSweep feature.
- `time`: Utilized for calculating round-trip times (RTT) in the Traceroute feature.
- `socket`: Used for the NSlookup feature.
- `scapy`: Employed for sending and receiving packets in the Traceroute feature.
- `tabulate`: Facilitates table formatting using fancy_grid format.
- `ping3`: Enables PingSweep functionality.

## Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/SApp-Network-Tool.git
cd SApp-Network-Tool

## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.