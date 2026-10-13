import pyshark

#load pcap file
def load_pcap(filename):
    return pyshark.FileCapture(filename)

#extract necessary data (port, time)
def extract_data(packet_list):

    data_list = []
    first_time = None

    for packet in packet_list:
        #ip adrr
        if "IP" not in packet:
            continue
        ip_source = packet.ip.src 
        ip_destination = packet.ip.dst

        #protocol 
        protocol = packet.ip.proto

        #time variable
        current_time = float(packet.sniff_timestamp)
        if first_time is None:
            first_time = current_time
        delta_time = current_time - first_time

        #destination port variable
        if "TCP" in packet:
            port = packet.tcp.dstport
            flags = packet.tcp.flags

        elif "UDP" in packet:
            port = packet.udp.dstport
            flags = None

        else:
            port = None
            flags = None

        #updating list ("data list")
        data_list.append({
            "ip_source": ip_source, 
            "ip_destination": ip_destination,
            "protocol": protocol,
            "time": delta_time, 
            "port": port,
            "flags": flags,
            })

    return data_list

#a thing for calculating the number of ports scanned per (?) seconds
def calculate_features(data_list, seconds):

    list_record = []
    TCP_flags = 0
    SYN_flags = 0
    RST_flags = 0

    #pockets for (?) time
    for packet in data_list:
        if packet['time'] > seconds:
            break
        list_record.append(packet)

    #calculating the unique ports
    unique_ports = {item['port'] for item in list_record if item['port'] is not None}
    unique_ports_nmb = len(unique_ports)

    #calculating the number of SYN flags compared to TCP flags
    for packet in list_record:
        if packet['protocol'] == '6':
            TCP_flags +=1

            flags = int(packet['flags'], 16)

            if flags == 0x0002:
                SYN_flags += 1
                
            if flags & 0x04: # if RST flag and smth else
                RST_flags += 1

    if TCP_flags > 0:        
        compared_SYN = SYN_flags / TCP_flags 
        compared_RST = RST_flags / TCP_flags 
    else: #if TCP_flags = 0
        compared_SYN = 0
        compared_RST = 0

    return {
        'unique_ports': unique_ports_nmb, 
        'unique_ports_per_second': unique_ports_nmb/seconds, 
        'compared_SYN': compared_SYN,
        'compared_RST': compared_RST,
        }

# the conclusion about data
def evaluate_traffic(calculated_list):

    points = 0

    if calculated_list['unique_ports_per_second'] > 20:
        points += 1

    if calculated_list['compared_SYN'] > 0.5:
        points += 1

    if calculated_list['compared_RST'] > 0.5:
        points += 1

    if points >= 2:
        return "Strong signs of port scanning"

    elif points == 1:
        return "Some signs of suspicious activity"

    elif points == 0:
        return "No strong signs detected"

##################

# A NORMAL CAP 1
file = load_pcap("http.cap") # a place for the filename!
data = extract_data(file)

#for i in data: 
#    print(i)

calculated_data = calculate_features(data, 10)
print(calculated_data)
print(evaluate_traffic(calculated_data))
file.close()

##################

# A NORMAL CAP 2

file = load_pcap("netbench_1.cap") # a place for the filename!
data = extract_data(file)

#for i in data: 
#    print(i)

calculated_data = calculate_features(data, 10)
print(calculated_data)
print(evaluate_traffic(calculated_data))
file.close()

##################

# NMAP SCANNING
file = load_pcap("nmap_standard_scan") # a place for the filename!
data = extract_data(file)

#for i in data: 
#    print(i)

calculated_data = calculate_features(data, 10)
print(calculated_data)
print(evaluate_traffic(calculated_data))
file.close()