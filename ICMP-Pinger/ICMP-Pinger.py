''' Skeleton Code - just need to fill in the blanks basically '''
from socket import *  # Low-level networking (sockets)
import os  # Retreive pids
import sys  # Check the system platform
import struct  # Packing/unpacking binary data into C-style structs
import time  # Timing
import select  # Monitoring socket events

ICMP_ECHO_REQUEST = 8  # IPCM type for Echo requests

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
        calcRTTs(rtt)
        
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

def ping(host: str, timeout: float =1) -> None:
    ''' Resolves a hostname to an IP, repeatedly (indefinitely) pings every second, prints response time
    Parameters:
    host- The hostname or IP address to ping
    timeout: Timeout in seconds for each ping'''
    global total_pings
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("To End Pinging, press ctrl+C")
    print("Pinging " + dest + " using Python:\n")

    # Send ping requests to a server separated by approximately one second
    try:
        while True:
            delay = doOnePing(dest, timeout)
            total_pings += 1
            print(delay)
            time.sleep(1)  # one second
        return delay
    except KeyboardInterrupt:
        print("\nPinging ended by user (keyboard interrupt)")
        print(f"Packet Loss: {(((total_pings - successful_pings) / total_pings) * 100)}% (Success: {successful_pings}/{total_pings})")
        print(f"Total RTT for {successful_pings} pings: {totalRTTs} ms")
        print(f"Average RTT: {totalRTTs/successful_pings} ms")
        print(f"Max RTT: {maxRTT}")
        print(f"Min RTT: {minRTT}\n")

def calcRTTs(cur_rtt: int) -> None:
    ''' Updates the total, minimum, and max RTTs (global) for end statistics
    Parameters:
    cur_rtt- The current rtt'''
    global totalRTTs, minRTT, maxRTT, successful_pings
    if minRTT == 0 or cur_rtt < minRTT:
        minRTT = cur_rtt
    if maxRTT == 0 or cur_rtt > maxRTT:
        maxRTT = cur_rtt
    totalRTTs += cur_rtt
    successful_pings += 1  # Aid in calculating packet loss, if RTT is calculated then successful

# Test Program
total_pings, successful_pings, totalRTTs, minRTT, maxRTT = 0, 0, 0, 0, 0
HOST = "jjmccauley.com"
# HOST = "127.0.0.1"  # Local Host
TIMEOUT = 1  # Default value for now
ping(HOST, timeout=TIMEOUT)  # Testing own website