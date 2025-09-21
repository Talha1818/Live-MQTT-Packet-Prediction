# Import necessary functions from the scapy.all library.
# get_if_list() is used to get a list of all network interface names.
# get_if_addr() is used to get the IP address associated with a specific interface.
from scapy.all import get_if_list, get_if_addr

# Iterate through each network interface in the list returned by get_if_list().
for iface in get_if_list():
    try:
        # Attempt to get the IP address for the current interface.
        # This is wrapped in a try-except block because some interfaces (like
        # a loopback or virtual interface) might not have an assigned IP address,
        # which would cause an error.
        print(iface, "->", get_if_addr(iface))
    except Exception:
        # If an error occurs (meaning no IP address was found),
        # print the interface name followed by "No IP".
        print(iface, "-> No IP")