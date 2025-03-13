# PYNetScan
*Efficient tool for identifying active and available IP addresses on your local network*

A Python-based network scanning tool with a graphical user interface (GUI) built using Tkinter. This tool automatically detects your local network, confirms it via pop-up dialogs, and scans for active and available IP addresses in real time. Double-click on any active IP to view additional network details—ideal for assessing devices (e.g., cameras) before connecting.

## Features

- **Automatic Local Network Detection and Confirmation**  
  - Detects your active adapter's IP address and subnet mask by parsing the output of `ipconfig` on Windows.
  - Displays a pop-up dialog to confirm the detected network. If incorrect, you can manually enter your network.
  - The confirmed network is cached for future runs.

- **Real-Time Scanning**  
  - Scans the detected network and updates two separate lists in real time:
    - **Active IPs:** Devices that respond to ping (with hostname information, when available).
    - **Available IPs:** IPs that do not respond.

- **Control Buttons**  
  - **Start:** Begin the scanning process.
  - **Pause/Resume:** Temporarily halt or resume scanning.
  - **Kill:** Immediately stop the scan.

- **Device Details**  
  - Double-click any active IP to open a new window displaying additional network details.
  - Details include the device's hostname and a quick scan of common camera-related ports (e.g., 80, 443, 554, 8000, 8001, 8080).

- **Standalone Executable Support**  
  - Build a standalone executable using PyInstaller so that the tool runs without a console window.
  - Current version .exe exists already in current repo.

## Requirements

- Python 3.x
- Tkinter (usually included with Python on Windows)
- [PyInstaller](https://www.pyinstaller.org/) (optional, for those who are building new iterations as an executable)

## Installation

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/yourusername/network-scanner-gui.git
   cd network-scanner-gui

## Usage
### Running from source
Run the tool by executing:

``` bash
python network_scanner_gui.py
```

**On the first run:**

-  A pop-up dialog will display the detected local network (e.g., 192.168.1.0/24). Confirm if it is correct.
-  If it’s not correct, enter your network manually when prompted.
-  The confirmed network is cached in a file named local_network.txt for subsequent runs.

**During scanning:**

-  Click Start to begin the scan.
-  Active and available IPs are updated in real time.
-  Use Pause/Resume to temporarily halt or resume scanning.
-  Click Kill to immediately stop the scan.
-  Double-click on any active IP to view additional details in a new window.

## Building a Standalone Executable
To build an executable without a console window:

```bash
pyinstaller --onefile --windowed network_scanner_gui.py
```

*The generated executable will be located in the dist directory and can be run on any Windows machine, even if Python is not installed.*

## Troubleshooting
Temporary Windows During Scanning:
The tool uses creationflags=subprocess.CREATE_NO_WINDOW when calling the ping command to ensure that no extra console windows appear.

Network Detection Issues:
If the auto-detected network is incorrect, simply input the correct network when prompted by the pop-up dialog. The chosen network is saved for future runs.

Permissions:
Running network scans may require administrator privileges in some environments.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
