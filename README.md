# Suricata Fuzzer

## Overview

The Suricata Fuzzer is a tool designed to test the Intrusion Detection and Prevention System (IDS/IPS) rules in Suricata by sending various TCP packets with different payloads and flags to a specified target IP and ports. The program logs the results of these tests, including which payloads triggered responses from Suricata, to help users understand and fine-tune their Suricata rules.

## GUI

![fup](https://github.com/user-attachments/assets/a7c8c3da-f82a-4ec4-a344-d966e173541e)

Here port scanning has been started for the provided destination IP:

![f1](https://github.com/user-attachments/assets/b8a639f0-9cba-41cd-86d7-d69dfbd6c4a6)

Here it shows port scanning results and fuzzing has been started on the resulting ports:

![f2](https://github.com/user-attachments/assets/38592d75-8869-4672-becd-2280345632ca)

Here are the results , as port 80 rule is not configured so it shows 0 percent probability that this
rule is not configured:

![f3](https://github.com/user-attachments/assets/9639648f-c028-4913-9d70-e923d0389b5a)

![f4](https://github.com/user-attachments/assets/ce5c7801-038d-4ba1-a557-a432770236c0)

Also shows result at the ending or fuzzing of each port:

![f5](https://github.com/user-attachments/assets/ab8d94cf-4270-44f5-a945-5322cfb14fb6)

Scrolling down shows results for others as well now navigating to view log files to view the logs
captured:

![f6](https://github.com/user-attachments/assets/0a86907b-bf3d-4e2d-93a0-ffa6fbeda222)

Scroll down to see remaining logs , now navigating to view jason file:

![f7](https://github.com/user-attachments/assets/ba2537f7-3c53-4fb4-9488-666caf988b43)

Navigating to view overall results file to see the summary of result:

![ff8](https://github.com/user-attachments/assets/3060e09e-99dc-4fc0-8f84-3436c32e2da8)

## Features

- **Random Payload Generation**: Generates random payloads to test the robustness of Suricata rules.
- **Port Scanning**: Scans a range of ports on the target IP to identify open and filtered ports.
- **Fuzzing**: Sends crafted TCP packets with different payloads and flags to the target IP and ports.
- **Logging**: Logs detailed information about each test, including sent packets and received responses.
- **Analysis**: Analyzes the responses to infer which Suricata rules might have been triggered.
- **GUI Interface**: Provides a user-friendly interface using Tkinter for easy interaction and visualization of results.

## Detailed Functionality

### Logging Configuration

-**Log File**: The program logs detailed information about the packets sent and responses received in **fuzzer.log**.
-**Log Level**: Set to DEBUG to capture all relevant information.

### Random Payload Generation

-**Function** : **`generate_random_payload(length)`**
-**Description**: Generates a random string of specified length using ASCII letters and digits.

### TCP Packet Crafting

-**Function**: create_tcp_packet(src_ip, dst_ip, src_port, dst_port, payload, flags="S")
-**Description**: Creates a TCP packet with the given source and destination IPs, ports, payload, and TCP flags.

### Packet Sending
-**Function**: send_packet(packet)
-**Description**: Sends a crafted packet and waits for a response with a timeout of 1 second.

### Connectivity Check
-**Function**: check_connectivity(target_ip)
-**Description**: Sends an ICMP ping to the target IP to check if it is reachable.

### Port Scanning
-**Function**: scan_ports(target_ip)
-**Description**: Scans ports 1-1024 on the target IP to identify open and filtered ports.
-**Output**: Lists of open and filtered ports.

### Suricata Fuzzing
-**Function**: fuzz_suricata(src_ip, src_port, target_ip, port)
-**Description**: Sends packets with different payloads and TCP flags to the target IP and port, then logs the responses.
-**Payloads**: Includes normal data, potential attack strings, and random payloads of lengths 50 and 100.
-**Flags**: Sends packets with various TCP flags (S, SA, A, F, P, R).

### Analysis and Inference
-**Function**: analyze_responses(results)
-**Description**: Analyzes the responses received from the target to infer potential IDS rules.
-**Rule Predictions**: Determines whether an IDS rule was likely triggered based on the responses.

### Results Storage
-**Files**: Results are stored in fuzzer_results.json and fuzzer__only_results.json.
-**Content**: Contains detailed information about each packet sent, including the payload, flags, response, and inferred rules.

### Number of Packets Sent
-**Description**: The number of packets sent depends on the number of payloads and flags tested. For each port, the fuzzer sends:
-5 payloads × 6 flags = 30 packets

### Graphical User Interface
-**Library**: Tkinter
-**Components**: Input fields for source IP, source port, target IP, and target ports, buttons to run fuzzing and view results, and an output text area to display logs and results.

## How to Use

1. **Run the Program**: Execute the script to open the GUI interface.
2. **Input Parameters**:
   - **Source IP**: Enter the source IP address.
   - **Source Port**: Enter the source port number.
   - **Target IP**: Enter the target IP address.
   - **Target Ports (Optional)**: Enter specific target ports to test, separated by commas or ranges (e.g., `80,443,1000-1010`).
3. **Run Fuzzing**: Click the "Run Fuzzing" button to start the fuzzing process.
4. **View Results**: Use the buttons to view detailed logs and JSON results.

## Code File

click here [fuzzer.py](fuzzer.py) for whole code:

The code file consists of the following main sections:

- **Configuration and Logging Setup**: Configures logging and sets up file paths for logs and results.
- **Random Payload Generation**: Functions to generate random payloads of specified lengths.
- **Packet Creation and Sending**: Functions to create TCP packets with specified parameters and send them.
- **Connectivity Check**: Function to check connectivity to the target IP.
- **Port Scanning**: Function to scan a range of ports on the target IP to identify open and filtered ports.
- **Fuzzing Suricata**: Function to fuzz Suricata with different payloads and flags, logging the results.
- **Response Analysis**: Function to analyze responses from Suricata and infer which rules might have been triggered.
- **Result Display and Saving**: Functions to display results in the GUI and save them to JSON files.
- **GUI Setup**: Code to create and configure the Tkinter GUI interface.

## Requirements

- Python 3.x
- Tkinter
- Scapy
- Logging
- JSON
- OS
- Time
- Random
- String

## Installation

1. **Install Python**: Ensure Python 3.x is installed on your system.
2. **Install Required Libraries**: Install the required Python libraries using pip:
   ```bash
   pip install tk scapy
   ```
3. **Download the Code**: Download or clone the repository containing the Suricata Fuzzer code.
   
## Contributions

No Contributions should be made without the permission of the author [Brooj-Nasir] .

## License

This project is licensed under the Proprietary License. See the LICENSE file for more details.

## Sample Code
```python

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
```
