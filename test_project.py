from project import pingsweep,traceroute, nslookup,check_ip_overlaps
import ipaddress

def main():
    test_pingsweep_reachable()
    test_pingsweep_unreachable()
    test_traceroute_valid()
    test_nslookup_valid()
    test_nslookup_invalid()

def test_pingsweep_reachable():
    # Tests pingsweep for a reachable host.
    result = pingsweep("8.8.8.8/32")  # used Google DNS
    expected_ip = "8.8.8.8"
    expected_status = "🟢"
    print("Actual Result:", result)  # Print the actual result for debugging purposes
    assert any(str(entry[0]) == expected_ip and entry[2] == expected_status for entry in result)

def test_pingsweep_unreachable():
    # Tests pingsweep for an unreachable host.
    # Assuming this range is unreachable due to a private class C range.
    result = pingsweep("192.168.1.1")
    expected_ip = "192.168.1.1"
    expected_status = "🔴"
    assert any(entry[0] == ipaddress.IPv4Address(expected_ip) and entry[2] == expected_status for entry in result)

def test_traceroute_valid():
    # Tests traceroute with a valid destination IP.
    # Assuming connectivity to this public DNS server
    result = traceroute("8.8.8.8")
    assert "8.8.8.8" in result  # Check if destination IP is present in results

def test_nslookup_valid():
    # Tests nslookup with a resolvable hostname.
    result = nslookup("iana.org")
    print("Actual Result:")
    for entry in result:
        print(entry)  # Print each entry for debugging purposes
    # Check if the resolved IP matches the expected IP and has a status of "🟢"
    expected_ip = "192.0.43.8"
    assert any(entry[1] == expected_ip and entry[2] == "🟢" for entry in result)

def test_nslookup_invalid():
    # Tests nslookup with an unresolvable hostname.
    result = nslookup("thishostnamedoesnotexist.com")
    print("Actual Result:")
    for entry in result:
        print(entry)  # Print each entry for debugging purposes
    # Check if the expected error message is contained in the result
    expected_error_message = "Error: [Errno 11001] getaddrinfo failed"
    actual_error_messages = [entry[1] for entry in result]
    assert any(expected_error_message in error_message for error_message in actual_error_messages), f"Expected Error Message: {expected_error_message}"

def test_determine_relationships():
    """
    Tests the determine_relationships function with various scenarios.
    """
    network1 = ipaddress.ip_network("192.168.1.0/24")
    network2 = ipaddress.ip_network("192.168.1.128/25")
    result = check_ip_overlaps([network1, network2])
    assert result == [["192.168.1.0/24", "192.168.1.128/25", "Overlaps"]]
    network3 = ipaddress.ip_network("192.168.0.0/25")
    network4 = ipaddress.ip_network("192.168.0.128/25")
    result = check_ip_overlaps([network3, network4])
    assert result == [["192.168.0.0/25", "192.168.0.128/25", "Unique"]]

if __name__ == "__main__":
    main()
