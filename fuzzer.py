import tkinter as tk
from tkinter import scrolledtext, messagebox
import scapy.all as scapy
import logging
import time
import random
import string
import json
import os

# Configure logging
LOG_FILE = 'fuzzer.log'
JSON_RESULT_FILE = 'fuzzer_results.json'
JSON_ONLY_RESULTS_FILE = 'fuzzer__only_results.json'

# Clear existing log file
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Function to create random payloads
def generate_random_payload(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Function to create TCP packet
def create_tcp_packet(src_ip, dst_ip, src_port, dst_port, payload, flags="S"):
    packet = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags=flags) / payload
    return packet

# Function to send packet and receive response
def send_packet(packet):
    response = scapy.sr1(packet, timeout=1, verbose=0)
    return response

# Function to check connectivity to the target IP
def check_connectivity(target_ip):
    ping = scapy.IP(dst=target_ip)/scapy.ICMP()
    response = scapy.sr1(ping, timeout=2, verbose=0)
    return response is not None

# Function to scan for open and filtered ports
def scan_ports(target_ip):

    port_scan = """
╔═╗┌─┐┬─┐┌┬┐  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┬┌┐┌┌─┐
╠═╝│ │├┬┘ │   ╚═╗│  ├─┤│││││││││││ ┬
╩  └─┘┴└─ ┴   ╚═╝└─┘┴ ┴┘└┘┘└┘┴┘└┘└─┘
    """

    output_text.tag_configure('center_white', justify='center', foreground='white')
    output_text.insert(tk.END, port_scan, 'center_white')
    output_text.insert(tk.END, "\n\n------------------------------------------------------------------\n\n", 'center_white')
    output_text.update_idletasks()

    ports = range(1, 1024)
    open_ports = []
    filtered_ports = []

    for port in ports:
        pkt = scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags='S')
        resp = send_packet(pkt)
        if resp is None:
            filtered_ports.append(port)
        elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == 'SA':
            open_ports.append(port)
    
    output_text.tag_configure('center_white', justify='center', foreground='white')
    output_text.insert(tk.END, f"Open ports found: {open_ports}\n", 'white')
    output_text.insert(tk.END, f"Filtered ports found: {filtered_ports}\n\n", 'white')
    output_text.insert(tk.END, "\n\n------------------------------------------------------------------\n\n", 'center_white')
    output_text.update_idletasks()

    return open_ports, filtered_ports

# Function to fuzz Suricata with different payloads and header values
def fuzz_suricata(src_ip, src_port, target_ip, port):
    payloads = [
        "normal data",
        "<script>alert('XSS')</script>",
        "' OR '1'='1'; --",
        generate_random_payload(50),
        generate_random_payload(100),
    ]
    flags_options = ["S", "SA", "A", "F", "P", "R"]

    results = []

    for payload in payloads:
        for flags in flags_options:
            packet = create_tcp_packet(src_ip, target_ip, src_port, port, payload, flags)
            response = send_packet(packet)
            sent_packet_hexdump = scapy.hexdump(packet, dump=True)
            response_packet_hexdump = scapy.hexdump(response, dump=True) if response else "No response"
            
            result = {
                'port': port,
                'payload': payload,
                'flags': flags,
                'response': response.summary() if response else "No response",
                'sent_packet': sent_packet_hexdump,
                'response_packet': response_packet_hexdump,
                'packet_summary': packet.summary()
            }

            results.append(result)
            print("Result:\n",result)
            
            # Log the results
            if response:
                logging.info(f'Sent packet to port {port} with payload: {payload}, flags: {flags}, response: {response.summary()}')
            else:
                logging.info(f'Sent packet to port {port} with payload: {payload}, flags: {flags}, response: No response')
            
            time.sleep(1)  # Ensure Suricata logs the packet

    return results

# Function to analyze responses and infer rules
def analyze_responses(results):
    rule_predictions = {}
    total_packets_sent = len(results)
    total_responses_received = sum(1 for result in results if "No response" not in result['response'])
    total_rules_triggered = total_packets_sent - total_responses_received
    main_port = 0

    for result in results:
        port = result['port']
        main_port = port
        if "No response" in result['response']:
            if port not in rule_predictions:
                rule_predictions[port] = {
                    'predicted_rule': "Likely rule triggered",
                    'details': []
                }
            rule_predictions[port]['details'].append({
                'payload': result['payload'],
                'flags': result['flags'],
                'response': "No response",
                'probability': "100%",
                'note': "This response indicates a high probability that an IPS rule is blocking the traffic.",
                'packet_summary': result['packet_summary'], 
                'sample_rule': f"alert tcp any any -> $HOME_NET {result['port']} (msg:\"IPS rule to block traffic for port {result['port']}\"; sid:1; rev:1;)"

            })
        else:
            if port not in rule_predictions:
                rule_predictions[port] = {
                    'predicted_rule': "No rule triggered",
                    'details': []
                }
            rule_predictions[port]['details'].append({
                'payload': result['payload'],
                'flags': result['flags'],
                'response': "Response received",
                'probability': "0%",
                'packet_summary': result['packet_summary'],
                'note': "The traffic passed through, indicating a low or zero probability of an IPS rule blocking this payload."
            })

        # Calculate overall score
    rule_detection_ratio = (total_rules_triggered / total_packets_sent) * 100 if total_packets_sent else 0
    if rule_detection_ratio == 100:   
        overall_score = {
            'total_packets_sent': total_packets_sent,
            'total_responses_received': total_responses_received,
            'total_rules_triggered': total_rules_triggered,
            'rule_detection_ratio': f"{rule_detection_ratio:.2f}%",
            'packet_summary': result['packet_summary'],
            'sample_rule': f"alert tcp any any -> $HOME_NET {main_port} (msg:\"IPS rule to block traffic for port {main_port}\"; sid:1; rev:1;)"
        }
    else:
        overall_score = {
            'total_packets_sent': total_packets_sent,
            'total_responses_received': total_responses_received,
            'total_rules_triggered': total_rules_triggered,
            'rule_detection_ratio': f"{rule_detection_ratio:.2f}%",
            'packet_summary': result['packet_summary'],
            'sample_rule': f"Based on the probability, it appears that no IPS rule is configured for port {main_port}, or the IPS was unable to block some of our payloads for this port."
        }
    # messagebox.showerror("Info", "Fuzzing Completed")

    return rule_predictions, overall_score

# Function to save results to JSON file
def save_results_to_json(predictions):
    with open(JSON_RESULT_FILE, 'a') as json_file:
        json.dump(predictions, json_file, indent=4)

def save_only_results_to_json(results):
    with open(JSON_ONLY_RESULTS_FILE, 'a') as json_file:
        json.dump(results, json_file, indent=4)

def display_only_results(output_text, display_results):
    output_text.tag_configure('center_white', justify='center', foreground='white')
    output_text.insert(tk.END, "------------------------------------------------------------------\n", 'center_white')
    output_text.insert(tk.END, f"Overall Result:\n", 'center_white')
    output_text.insert(tk.END, "------------------------------------------------------------------\n", 'center_white')
    output_text.update_idletasks()
    output_text.insert(tk.END,display_results, 'white')
    output_text.insert(tk.END,"\n\n", 'white')
    output_text.update_idletasks()

# Function to display results in the GUI output window
def display_results(output_text, port, predictions):
    output_text.tag_configure('center_white', justify='center', foreground='white')
    output_text.insert(tk.END, "------------------------------------------------------------------\n", 'center_white')
    output_text.insert(tk.END, f"Fuzzing Results for Port: {port}\n", 'center_white')
    output_text.insert(tk.END, "------------------------------------------------------------------\n", 'center_white')
    output_text.update_idletasks()

    prediction = predictions.get(port, {})
    for detail in prediction.get('details', []):
        output_text.insert(tk.END, f"  Payload: {detail['payload']}\n", 'white')
        output_text.insert(tk.END, f"  Flags: {detail['flags']}\n", 'white')
        output_text.insert(tk.END, f"  Response: {detail['response']}\n", 'white')

        if detail['probability'] == "100%":
            output_text.insert(tk.END, f"  Probability: {detail['probability']}\n", 'red')
            output_text.insert(tk.END, f"  Note: {detail['note']}\n\n", 'red')
        else:
            output_text.insert(tk.END, f"  Probability: {detail['probability']}\n", 'green')
            output_text.insert(tk.END, f"  Note: {detail['note']}\n\n", 'green')

    output_text.tag_configure('center_white', justify='center', foreground='white')
    output_text.insert(tk.END, "------------------------------------------------------------------\n", 'center_white')
    output_text.update_idletasks()

# Function to clear output and run fuzzing
def clear_and_run_fuzzing(output_text, src_ip, src_port, target_ip, target_ports_entry):
    output_text.config(state=tk.NORMAL)
    output_text.delete('1.0', tk.END)
    output_text.config(state=tk.DISABLED)
    run_fuzzing(output_text, src_ip, src_port, target_ip, target_ports_entry)

# clear files to store results of current fuzzing only
def clear_file_contents(file_path):
    with open(file_path, 'w') as file:
        # Opening a file in 'w' mode truncates it, effectively clearing its contents
        pass

# Function to run the fuzzing and analysis process
def run_fuzzing(output_text, src_ip, src_port, target_ip, target_ports_entry):
    if not check_connectivity(target_ip):
        messagebox.showerror("Error", f"Cannot reach the target IP {target_ip}. Please check the network connection and try again.")
        return
    
    # Clear the contents of the JSON and log files to store results of current fuzzing task
    clear_file_contents(LOG_FILE)
    clear_file_contents(JSON_RESULT_FILE)
    clear_file_contents(JSON_ONLY_RESULTS_FILE)

    output_text.config(state=tk.NORMAL)

    fuz_msg = """
███████╗██╗   ██╗███████╗███████╗██╗███╗   ██╗ ██████╗ 
██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║████╗  ██║██╔════╝ 
█████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██╔██╗ ██║██║  ███╗
██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║╚██╗██║██║   ██║
██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝
╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
 \n\n                                                   
"""

    output_text.tag_configure('center_white', justify='center', foreground='white')
    output_text.insert(tk.END, fuz_msg + "\n", 'center_white')
    output_text.update_idletasks()

    if target_ports_entry:
        target_ports = parse_ports(target_ports_entry)
    else:
        open_ports, filtered_ports = scan_ports(target_ip)
        target_ports = open_ports + filtered_ports

    for port in target_ports:
        output_text.tag_configure('center_white', justify='center', foreground='white')
        output_text.insert(tk.END, f"Starting fuzzing for port: {port}\n", 'center_white')
        output_text.insert(tk.END, "------------------------------------------------------------------\n", 'center_white')
        output_text.update_idletasks()

        results = fuzz_suricata(src_ip, src_port, target_ip, port)
        predictions, results1 = analyze_responses(results)
        final_result_port = {"port":port,
                             "result":results1}

        display_results(output_text, port, predictions)
        save_results_to_json(predictions)
        display_only_results(output_text, final_result_port)
        save_only_results_to_json(final_result_port)

    output_text.config(state=tk.DISABLED)

# Function to open and display the log file
def view_log_file(output_text):
    output_text.config(state=tk.NORMAL)
    output_text.delete('1.0', tk.END)
    
    with open(LOG_FILE, 'r') as log_file:
        output_text.insert(tk.END, log_file.read(), 'white')

    output_text.config(state=tk.DISABLED)

# Function to open and display the JSON result file
def view_json_file(output_text):
    output_text.config(state=tk.NORMAL)
    output_text.delete('1.0', tk.END)
    
    with open(JSON_RESULT_FILE, 'r') as json_file:
        output_text.insert(tk.END, json_file.read(), 'white')

    output_text.config(state=tk.DISABLED)

# Function to open and display the JSON ONLY result file
def view_only_json_file(output_text):
    output_text.config(state=tk.NORMAL)
    output_text.delete('1.0', tk.END)
    
    with open(JSON_ONLY_RESULTS_FILE, 'r') as json_file:
        output_text.insert(tk.END, json_file.read(), 'white')

    output_text.config(state=tk.DISABLED)

# Function to parse port input string into a list of ports
def parse_ports(port_input):
    target_ports = []
    for item in port_input.split(','):
        if '-' in item:
            start, end = map(int, item.split('-'))
            target_ports.extend(range(start, end + 1))
        else:
            target_ports.append(int(item))
    return target_ports

# Function to display welcome message
def display_welcome_message(output_text):
    welcome_message = """\n\n\n\n\n

██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗
██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝
██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗  
██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝  
╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗
 ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
                                                              
"""
    welcome_message_2 = """\n\n\t\t\t
╔╗ ┬ ┬  ╔╗ ┬─┐┌─┐┌─┐ ┬
╠╩╗└┬┘  ╠╩╗├┬┘│ ││ │ │
╚═╝ ┴   ╚═╝┴└─└─┘└─┘└┘

"""
    output_text.config(state=tk.NORMAL)
    output_text.tag_configure("center", justify="center", foreground="white")
    output_text.insert(tk.END, welcome_message, "center")
    output_text.insert(tk.END, welcome_message_2, "center")
    output_text.config(state=tk.DISABLED)

# Create the main Tkinter window
root = tk.Tk()
root.title("Suricata Fuzzer")

# Create frames for input and output sections
input_frame = tk.Frame(root, padx=10, pady=10)
input_frame.grid(row=0, column=0, sticky="nsew")

output_frame = tk.Frame(root, padx=10, pady=10)
output_frame.grid(row=0, column=1, sticky="nsew")

# Configure grid layout
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=20)
root.grid_rowconfigure(0, weight=1)

# Input fields
tk.Label(input_frame, text="Source IP:").grid(row=0, column=0, sticky="w")
src_ip_entry = tk.Entry(input_frame)
src_ip_entry.grid(row=0, column=1, sticky="ew")

tk.Label(input_frame, text="Source Port:").grid(row=1, column=0, sticky="w")
src_port_entry = tk.Entry(input_frame)
src_port_entry.grid(row=1, column=1, sticky="ew")

tk.Label(input_frame, text="Target IP:").grid(row=2, column=0, sticky="w")
target_ip_entry = tk.Entry(input_frame)
target_ip_entry.grid(row=2, column=1, sticky="ew")

tk.Label(input_frame, text="Target Ports (Optional):").grid(row=3, column=0, sticky="w")
target_ports_entry = tk.Entry(input_frame)
target_ports_entry.grid(row=3, column=1, sticky="ew")

# Buttons
fuzz_button = tk.Button(input_frame, text="Run Fuzzing", command=lambda: clear_and_run_fuzzing(output_text, src_ip_entry.get(), int(src_port_entry.get()), target_ip_entry.get(), target_ports_entry.get()))
fuzz_button.grid(row=4, column=0, columnspan=2, pady=5, sticky="ew")

view_log_button = tk.Button(input_frame, text="View Log File", command=lambda: view_log_file(output_text))
view_log_button.grid(row=5, column=0, columnspan=2, pady=5, sticky="ew")

view_json_button = tk.Button(input_frame, text="View JSON File", command=lambda: view_json_file(output_text))
view_json_button.grid(row=6, column=0, columnspan=2, pady=5, sticky="ew")

view_json_button = tk.Button(input_frame, text="View Overall Results", command=lambda: view_only_json_file(output_text))
view_json_button.grid(row=7, column=0, columnspan=2, pady=5, sticky="ew")

# Output window
output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, state=tk.DISABLED, bg="darkblue", fg="white")
output_text.pack(fill=tk.BOTH, expand=True)

# Define tag styles for colored output
output_text.tag_configure('white', foreground='white')
output_text.tag_configure('red', foreground='red')
output_text.tag_configure('green', foreground='green')

# Display the welcome message
display_welcome_message(output_text)

# Run the Tkinter main loop
root.mainloop()

