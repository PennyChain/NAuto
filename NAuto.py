# NAuto - "Nmap - Auto"
import subprocess, time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor


print(r"""
      
    .-._         ,---.                      ,--.--------.   _,.---._     
    /==/ \  .-._.--.'  \     .--.-.  .-.-. /==/,  -   , -\,-.' , -  `.   
    |==|, \/ /, |==\-/\ \   /==/ -|  /=/  |\==\.-.  - ,-./==/_,  ,  - \  
    |==|-  \|  |/==/-|_\ |  |==| ,|  |=| -|`--`\==\- \ |==|   .=.     | 
    |==| ,  | -|\==\,   - \ |==|- |  =/   |     \==\_ \|==|_ : ;=:  - | 
    |==| -   _ |/==/ -   ,| |==|,  \_/ - |      |==|- ||==| , '='     | 
    |==|  /\ , /==/-  /\ - \|==|-   ,   /      |==|, |  \==\ -    ,_ /  
    /==/, | |- \==\ _.\=\.-'/==/ , _  .'      /==/ -/    '.='. -   .'   
    `--`./  `--``--`        `--`..---'        `--`--`      `--`--''     
                                                          
                              Nmap - Auto
""")


userChoice = input("Start: (y/n) ")

if userChoice == "y":

    # Target IP's (Only do this with IP's you have permission to scan)
    with open('targets.txt', 'r') as targets_file:
        targets = []
        vlanIDs = []
        for line in targets_file:
            line = line.strip()
            if line and "," in line:
                ip, vlan = line.split(",")
                targets.append(ip.strip())
                vlanIDs.append(vlan.strip())


    # Creating directories and running nmap-commands
    def scan_target(target, vlanID):
        os_command1 = f"mkdir -p result_VLAN{vlanID}"
        # Default port scan
        nmap_command1 = f"sudo nmap -A -T4 -v {target} -oA result_VLAN{vlanID}/result"
        subprocess.run(os_command1, capture_output=True, shell=True, text=True)
        try:
            print(f"Scanning: {target} VLAN: {vlanID}")
            subprocess.run(nmap_command1, capture_output=True, shell=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running nmap_command1: {e}")
            return
        except Exception as e:
            print(f"Unexpected error: {e}")
            return

        try:
            print(f"Parsing: result_VLAN{vlanID}/result.xml")
            tree = ET.parse(f"result_VLAN{vlanID}/result.xml")
        except ET.ParseError as e:
            print(f"XML parsing failed: {e}")
            return

        root = tree.getroot()

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") == "up":
                address = host.find("address")
                if address is not None:
                    ip_addr = address.get("addr")
                    # Open ports from scanned IP's
                    open_ports = []
                    for port in host.findall(".//port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            portid = port.get("portid")
                            open_ports.append(portid)
                    if open_ports:
                        ports_str = ",".join(open_ports)
                        ip_no_cidr = ip_addr.split("/")[0]
                        safe_ip = ip_no_cidr.replace(".", "_")
                        os_command2 = f"mkdir result_VLAN{vlanID}/{safe_ip}"
                        subprocess.run(os_command2, capture_output=True, shell=True, text=True)
                        # Vulnerability check
                        nmap_command2 = f"sudo nmap -Pn -sV -p{ports_str} --version-intensity 9 --script=vulners,safe {ip_addr} -oA result_VLAN{vlanID}/{safe_ip}/{safe_ip}_vulncheck"
                        try:
                            print(f"Starting vulncheck: {ip_addr}")
                            subprocess.run(nmap_command2, capture_output=True, shell=True, text=True, check=True)
                        except subprocess.CalledProcessError as e:
                            print(f"Error running nmap_command2: {e}")
                        except Exception as e:
                            print(f"Unexpected error: {e}")

    # Async
    with ThreadPoolExecutor(max_workers=3) as executor:
        for target, vlanID in zip(targets, vlanIDs):
            executor.submit(scan_target, target, vlanID)

elif userChoice == "n":
    print("Quitting\n")

else:
    print("Enter either 'y' or 'n'\n")