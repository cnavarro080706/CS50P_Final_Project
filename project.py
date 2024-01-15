"""
SApp(SimpleApp) Network tool (version 1.0)
A Simple command-line tool design for basic network diagnostics.

Features:
- PingSweep: Scans a specified IP range to determine reachable hosts.
- Traceroute: Traces the path to a destination IP, displaying RTTs for each hop.
- NSlookup: Resolves a hostname to its corresponding IP address(es).
- Check IP Overlaps : This feature of ipaddress module revalidates if ipv4 addresses either single host to a range of subnets that will determine whether or not both network 1 and network 2 have potential overlapping  issue.

Author: Christopher Edmund B. Navarro
Github/edX Username: cnavarro080706
Address: Antipolo City, Rizal, Philippines
Date: January 08, 2024
City and Country: Antipolo City, Rizal, Philippines, 1870
"""
# Import for executing computer system commands
import sys
import ipaddress    # Used this module for the pingsweep and ip overlaps feature
import time         # Used this module for the traceroute() rtt(round trip time)
import socket       # Used this module for the nslookup feature
from scapy.all import sr1,IP,ICMP  # Used this module for the traceroute feature
from tabulate import tabulate  # For table formatting
from ping3 import ping  # Used this module for the pingsweep feature

def main():
    """
    Main fucntion to execute SApp Network Tool.
    """
    # created an infinite loop to ask user-define selection 
    while True:
        print(dashboard())
        user_choice = input("Enter your choice: ")

        if user_choice == "1":
            ipv4_add = input("Enter target IP range (e.g., 192.168.1.0/24): ")
            results = pingsweep(ipv4_add)
            # formatting of the table for display
            headers = ["IP Address", "Latency(ms)", "Reachability Status"]
            # Print the formatted table
            print(tabulate(results, headers=headers, tablefmt="fancy_grid",stralign="center", numalign="center"))
            sys.exit("Successfully Completed!")

        elif user_choice == "2":
            # Gets user input, calls traceroute(), and displays results.
            destination_ip = input("Enter the destination IP address (e.g., 192.168.0.1): ")
            number_of_hops = int(input("Enter the number of hops(default is 12): ")or 12)  # Allow empty input for default
            results = traceroute(destination_ip, max_hops=number_of_hops)
            # Create a list of lists for table formatting
            table_data = []
            for line in results.splitlines():
                hop_count, rtt1, rtt2, rtt3, next_hop_router = line.split()
                table_data.append([hop_count, rtt1, rtt2, rtt3, next_hop_router])
            # Print the formatted table
            headers=["Hop Count", "RTT1 (ms)", "RTT2 (ms)", "RTT3 (ms)", "Next Hop Router"]
            print(tabulate(table_data, headers=headers, tablefmt="fancy_grid", stralign="center", numalign="center"))
            sys.exit("Successfully Completed!")

        elif user_choice == "3":
            # Gets user input, calls nslookup(), and displays results.
            # make iana.org as default website to lookup incase user forgot to enter an input.
            hostname = input("Enter the hostname to lookup (e.g., iana.org): ")or "iana.org"
            results = nslookup(hostname)
            # formatting of the table for display
            headers=["Hostname or FQDN", "Resolved IP Address", "Status"]
            col_widths = [20, 20, 20]
            print(tabulate(results, headers=headers,tablefmt="fancy_grid", stralign="center", numalign="center"))
            sys.exit("Successfully Completed!")

        elif user_choice == "4":
            """
            Collects IP addresses or ranges from the user and displays their relationships.
            """
            ip_networks = []
            while True:
                ip_or_range = input("Enter an IP address or range (or 'done' to finish): ")
                if ip_or_range.lower() == "done":
                    break
                try:
                    ip_network = ipaddress.ip_network(ip_or_range)
                    ip_networks.append(ip_network)
                except ValueError:
                    print("Invalid IP address or range. Please try again.")

            if len(ip_networks) < 2:
                print("Need at least two IP addresses or ranges to check for overlaps.")
                return

            relationships = check_ip_overlaps(ip_networks)
            headers = ["Network 1", "Network 2", "Relationship"]
            if relationships:
                print(tabulate(relationships, headers=headers, tablefmt="fancy_grid", stralign="center", numalign="center"))
                sys.exit("Successfully Completed!")

        elif user_choice == "5":
            sys.exit("Exiting the application...")

        else:
            print("Invalid choice. Please try again.")

def dashboard():
    """
    Displays the main menu of the SApp Network Tool.
    """
    display = """
    ##########################################
    #        SApp Network Tool v1.0          #
    ##########################################
    # [1] PingSweep                          #
    # [2] Traceroute                         #
    # [3] NSlookup                           #
    # [4] Check IP Overlaps                  #
    # [5] Quit                               #
    ##########################################
    """
    return display

def pingsweep(target_ip_range):
    """
    Performs a ping sweep on a specified IP range.
    Args:
        target_ip_range (str): The target IP range in CIDR notation (e.g., 192.168.1.0/24).
    Returns:
        list: A list of lists containing IP addresses, latencies, and reachability status.
    """
    legend = """
            ############################
            #   🟢  -  Reachable       #
            #   🔴  -  Not Reachable   #
            ############################
            """
    print(legend)
    result_table = []   # initialize empty variable
    try:
        prefix = ipaddress.ip_network(target_ip_range)
        for host in prefix.hosts():  # Iterating through the “usable” addresses on a provided prefix:
            latency = ping(str(host), timeout=1) # Convert host to string before passing to ping
            if latency is not None:
                status = "🟢"
                latency = round(latency * 1000, 3)
            else:
                status = "🔴"  # If timed out (no reply), returns None, in the terminal - returns blank
            result_table.append([host, latency, status]) # appending the empty list result_table
        return result_table
    except ValueError:
        sys.exit("IP Address range is incorrect. Please try again.")

def traceroute(destination_ip, max_hops=12):
    """
    Performs a traceroute to the specified destination IP.
    Args:
        destination_ip (str): The destination IP address to traceroute to.
        max_hops (int, optional): The maximum number of hops to trace. Defaults to 12.
    Returns:
        str: A formatted string representing the traceroute results.
    """
    results = ""  # initialize empty variable to capture the traceroute result
    for ttl in range(1, max_hops + 1):
        try:
            rtts = []  # Store RTTs for the current hop
            for i in range(3):
                packet = IP(dst=destination_ip, ttl=ttl) / ICMP()  # Create ICMP packet with TTL
                start_time = time.time()
                response = sr1(packet, timeout=1, verbose=False)  # Send and receive response
                end_time = time.time()
                rtt = (end_time - start_time) * 1000  # Calculate RTT in milliseconds
                rtts.append(rtt)
            if response is None:  # Timeout
                next_hop_router = "*"
            else:
                next_hop_router = response.src  # Get next hop router's IP from response
            # Format results for the current hop
            results += f"{ttl}\t{rtts[0]:.2f}\t{rtts[1]:.2f}\t{rtts[2]:.2f}\t{next_hop_router}\n"
        except Exception as e:
            results += f"{ttl}\tError: {str(e)}\n"  # Handle other exceptions
    return results

def nslookup(hostname):  
    """
    Performs a DNS lookup for the given hostname.
    Args:
        hostname (str): The hostname to resolve.
    Returns:
        list: A list of lists containing the hostname, resolved IP addresses, and resolution status.
    """
    legend = """
            #################################
            #   🟢  -  Resolved            #
            #   🔴  -  Non-existent domain #
            #################################
            """
    print(legend)
    # Performs an NS lookup for the given hostname and returns the resolved IP address(es).
    try:
        # Use gethostbyname_ex for more comprehensive results
        results = socket.gethostbyname_ex(hostname)
        ip_addresses = results[2]  # Extract IP addresses

        if ip_addresses:
            return [[hostname, ip, "🟢"] for ip in ip_addresses]  # Create list of lists for table
        else:
            return [[hostname, "No IP addresses found.", "No"]]
    # capturing the potential error. gaierror, a subclass of OSError, this exception is raised for address-related errors
    except socket.gaierror as e: 
        return [[hostname, f"Error: {e}", "🔴"]]
    
def determine_relationships(network1, network2):
    """
    Determines the relationship between two IP networks.

    Args:
        network1: An ipaddress.ip_network object.
        network2: An ipaddress.ip_network object.

    Returns:
        A string describing the relationship between the networks,
        such as "Overlaps", "Network 1 contains Network 2", etc.
    """
    if network1.overlaps(network2):
        return "Overlaps"
    elif network1.supernet_of(network2):
        return "Network 1 contains Network 2"
    elif network2.supernet_of(network1):
        return "Network 2 contains Network 1"
    else:
        return "Unique"

def check_ip_overlaps(ip_networks):
    """
    Checks for relationships between all pairs of IP networks.

    Args:
        ip_networks: A list of ipaddress.ip_network objects.

    Returns:
        A list of lists, where each inner list represents a row in the table
        containing Network 1, Network 2, and their relationship.
    """
    table_data = []
    for ip_address1 in range(len(ip_networks) - 1):
        for ip_address2 in range(ip_address1 + 1, len(ip_networks)):
            network1 = ip_networks[ip_address1]
            network2 = ip_networks[ip_address2]
            relationship = determine_relationships(network1, network2)
            table_data.append([str(network1), str(network2), relationship])
    return table_data

if __name__ == "__main__":
    main()
