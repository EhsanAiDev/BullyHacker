## What is this script?
This Python script is designed to counteract hackers by detecting their activity while they scan a network or web server.

## What does it do?
The script functions as a firewall that monitors network traffic through the NIC (Network Interface Controller).
It detects potential hackers by analyzing the traffic and identifying malicious behavior.
Once a hacker is detected, their IP address is added to a blacklist, and any further packet requests from that IP are dropped.
Additionally, if the blocked hacker attempts to send TCP packets again, the script retaliates by sending a TCP packet back to the hacker's IP and port containing a "bullying" message.
