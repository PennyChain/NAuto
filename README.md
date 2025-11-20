# NAuto

![Project Logo](images/logo.png)

NAuto is a tool designed to automate network tasks and streamline processes related to network device management. The repository is structured for extensibility and ease of use, providing users with a simple way to define and manage network targets through configuration files.

## Features

- Automates common network management tasks.
- Simple target configuration using a `targets.txt` file.
- Easy-to-use interface for managing devices by IP and VLAN ID.

## Getting Started

1. **Clone the repository:**
   ```sh
   git clone https://github.com/PennyChain/NAuto.git
   cd NAuto
   ```

2. **Install dependencies:**
     ```
     pip install -r requirements.txt
     ```
   - Ensure you have the required runtime and dependencies according to your project's language (check specific language setup below).

4. **Setup your targets list:**
   - Create a file named `targets.txt` in the project root directory.
   - Add one target per line, using the format:  
     ```
     ip/cidr, vlanid
     ```
     Example:
     ```
     192.168.10.0/23, 10
     192.168.20.0/24, 20
     ```

5. **Run the tools:**
     ```
     python3 NAuto.py
     python3 Document.py
     ```
   - Refer to the documentation or main entrypoint for instructions on executing the automation tasks.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests. Please ensure any new code is well-documented and tested.

## License

This project is licensed under the terms of the repository's LICENSE file.

---
