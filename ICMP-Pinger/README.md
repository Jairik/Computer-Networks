# Socket Programming - ICMP Pinger

This application uses the Internet Control Message Protocol (ICMP) to implement a pinger application, sending ICMP request and reply messages.
Users can provide hostnames/IPs, timeout, and number of pings are arguments to the script, reporting back statistics such as average RTT and Packet loss.

![Demo Picture using jjmccauley.com as Hostname, 5 second timeout, and 5 total pings](/ICMP-Pinger/Documentation-and-References/Demo-picture.png)

Note: For complexity reasons, this application will not follow official RFC 1739 specifications.
