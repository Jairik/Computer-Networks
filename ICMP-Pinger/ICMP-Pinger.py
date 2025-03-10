''' ICMP Pinger - JJ McCauley - Last Updated 3/10/25 '''
from socket import *  # Low-level networking (sockets)
import os  # Retreive pids
import sys  # Check the system platform
import struct  # Packing/unpacking binary data into C-style structs
import time  # Timing
import select  # Monitoring socket events
import statistics  # For easy RTT statistic calculations
import argparse  # For accepting command line arguments

ICMP_ECHO_REQUEST = 8  # IPCM type for Echo requests
rtt_list = []  # List to hold various RTTs for statistics calculations
total_pings = 0  # Total number of pings actually executed

def checksum(source_string) -> int:
    ''' Computes the internet checksum used by ICMP for error detection
        Parameter: source_string- Represents binary data for packet (ICMP header & data) 
        Returns: The 16-bit checksum, used for error detection '''
    
    # Convert to bytes if needed
    if isinstance(source_string, str):
        source_string = source_string.encode()
    
    csum = 0
    countTo = (len(source_string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = source_string[count + 1] * 256 + source_string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(source_string):
        csum = csum + source_string[len(source_string) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    
    return answer

def receiveOnePing(mySocket: socket, ID: int, timeout: float, destAddr: str) -> str:
    ''' Waits for an ICMP Echo Reply (pong), extracting the response header, verified ID, and calculates RTT if valid
    Parameters:
    mySocket- The raw socket used to receive packets
    ID- Identifier for packets
    timeout- Maximum time to wait for a response before timing out
    destAddr- Distrination IP address being pinged 
    Returns: A string message '''
    
    timeLeft = timeout

    while True:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)

        if whatReady[0] == []:  # Timeout
            return "Request timed out when receiving (start)."

        timeReceived = time.perf_counter()
        recPacket, addr = mySocket.recvfrom(1024)
        
        # Ensure that the packet is at least 28 bytes (20 byte IP header, 8 byte ICMP header)
        if len(recPacket) < 28:
            return "Packet is too short"

        # Extract the ICMP Header
        icmpHeader = recPacket[20:28]  # Extract 8-byte ICMP Header, skipping 20-byte IP header
        icmpType, icmpCode, icmpChecksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
        # Where icmpType should be 0 for Echo Reply, and packetID should match the ID from packet sent
        
        # Validate the ICMP Response 
        if icmpType != 0:
            # Interpret ICMP Error Code
            if icmpType == 3:
                if icmpCode == 0:
                    return "Destination Network Unreachable"
                elif icmpCode == 1:
                    return "Destination Host Unreachable"
                else:
                    return f"Destination Unreachable, code {icmpCode}"
        elif packetID != ID:
            return "Packet ID does not match, ignoring."
        
        # Ensure the packet has enough bytes for a timestamp
        if len(recPacket) < 28 + struct.calcsize("d"):
            return "Received packet does not contain a valid timestamp"
        
        # Extract the timestamp and compute RTT (in ms)
        timeSent = struct.unpack("d", recPacket[28:28 + struct.calcsize("d")])[0]  # Extracting the timestamp
        rtt = (timeReceived - timeSent) * 1000  # Computing RTT & converting to ms
        
        # Ensure time elasped doesn't cause timeout
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out when receiving."
        
        # Update RTTs (total, min, max)
        rtt_list.append(rtt)
        
        # Return message containing rtt
        return f"Reply from {destAddr}: time={rtt}ms"

def sendOnePing(mySocket: socket, destAddr: str, ID: int) -> None:
    ''' Constructs & Sends an ICMP Echo Request with a timestamp, computing checksum and sending it to its destination
    Parameters:
    mySocket- The raw socket used to send packets
    destAddr- Destination IP address
    ID: Identifier for packets '''
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0

    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.perf_counter())

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str

def doOnePing(destAddr: str, timeout: int) -> str:
    ''' Creates a raw socket, sends a ping, waits for a response, records delay, and closes socket
    Parameters:
    destAddr- Destination IP address being pinged 
    timeout- Max time to wait for a response
    Returns: The response message (RTT or timeout message) '''
    icmp = getprotobyname("icmp")
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF  # Return the current process ID

    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay

def ping(host: str = "127.0.0.1", timeout: float = 1, NUM_PINGS: int = 10**100) -> None:
    ''' Resolves a hostname to an IP, repeatedly pings every second, prints response time
    Parameters:
    host- The hostname or IP address to ping
    timeout- Timeout in seconds for each ping
    NUM_PINGS- The amount of pings to send to host, essentially set to infinity as default value '''
    global total_pings
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("To end pinging early, press ctrl+c")
    print("Pinging " + dest + " using Python:\n")

    # Send ping requests to a server separated by approximately one second
    try:
        for i in range(NUM_PINGS):
            delay = doOnePing(dest, timeout)
            total_pings += 1
            print(delay)
            time.sleep(1)  # one second
    except KeyboardInterrupt:
        # Once user sends keyboard interrupt, show statistics
        print("\nPinging ended by user (keyboard interrupt)")
    print("\n---------------------------------------------------------------------")
    print(f"Packet Loss: {(((total_pings - len(rtt_list)) / total_pings) * 100)}% (Success: {len(rtt_list)}/{total_pings})")
    print(f"Total RTT for {len(rtt_list)} pings: {sum(rtt_list)} ms")
    print(f"Average RTT: {sum(rtt_list)/len(rtt_list)} ms")
    print(f"Max RTT: {max(rtt_list)} ms")
    print(f"Min RTT: {min(rtt_list)} ms")
    print(f"RTT Standard Deviation: {statistics.stdev(rtt_list)} ms")
    # Calculating the 'jitter', which is the variability between successive RTTs
    if len(rtt_list) > 1:
        jitters = [abs(rtt_list[i] - rtt_list[i-1]) for i in range(1, len(rtt_list))]
        average_jitter = sum(jitters) / len(jitters)
    else: 
        average_jitter = 0  # Less than 2 pings
    print(f"Jitter: {average_jitter} ms")
    print("---------------------------------------------------------------------\n")

    return delay

# Adding capability for command line arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPMP Pinger")  # Adding Argument Parser
    parser.add_argument("host", nargs="?", type=str, default='127.0.0.1', help="Hostname or IP address to ping (default: 127.0.0.1)")  # Hostname Argument
    parser.add_argument("timeout", nargs="?", type=float, default=1, help="Timeout in seconds for each ping (default: 1)")  # Timeout Argument
    parser.add_argument("pings", nargs="?", type=int, default=8, help="Number of total pings to send (default: 8)")  # Number Pings Argument
    args = parser.parse_args()

# Testing Program
HOST = args.host
TIMEOUT = args.timeout
NUM_PINGS = args.pings
    
ping(host=HOST, timeout=TIMEOUT, NUM_PINGS=NUM_PINGS)