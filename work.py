import pyshark
import matplotlib.pyplot as plt

def extract_metrics(pcap_file):
    throughput = []  # List to store throughput values
    latency = []     # List to store latency values
    packet_loss = [] # List to store packet loss values

    capture = pyshark.FileCapture(pcap_file)

    previous_time = None
    total_bytes = 0

    for packet in capture:
        # Calculate throughput
        if 'ip' in packet and 'length' in packet['ip']:
            total_bytes += int(packet['ip'].length)
            if previous_time:
                time_diff = float(packet.sniff_time) - previous_time
                throughput.append(total_bytes / time_diff)  # Bytes per second
            previous_time = float(packet.sniff_time)

        # Calculate latency
        if 'response_in' in packet:
            response_time = float(packet.response_in)
            latency.append(response_time)

    capture.close()

    return throughput, latency

def plot_metrics(throughput, latency):
    plt.figure(figsize=(10, 5))

    # Plot Throughput
    plt.subplot(2, 1, 1)
    plt.plot(throughput, color='blue')
    plt.title('Throughput')
    plt.xlabel('Packet Number')
    plt.ylabel('Throughput (Bytes/Second)')

    # Plot Latency
    plt.subplot(2, 1, 2)
    plt.plot(latency, color='green')
    plt.title('Latency')
    plt.xlabel('Packet Number')
    plt.ylabel('Latency (Seconds)')

    plt.tight_layout()
    
    # Save plot as PNG
    plt.savefig('metrics_plot.png')

# Replace 'your_file.pcap' with the path to your .pcap file
throughput, latency = extract_metrics('packets(47999_49006).pcapng')
plot_metrics(throughput, latency)
