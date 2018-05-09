# octopi
This utility uses the Python bindings to NetfilterQueue to hook into iptables and make every port on a machine appear open.  It also has the capability to forward traffic to ports that are actually open on the machine.

Octopi has the ability to be remotely configured on a machine, such as adding valid open ports to pass traffic to and toggling capabilities.

# Scans it works on
As of now, it only works for TCP Connect Scans, but I plan on adding UDP scanning capability.
