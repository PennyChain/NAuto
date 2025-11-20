import subprocess, time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

import xml.etree.ElementTree as ET


print(r"""
      
    ███▄▄▄▄   ████████▄   ▄██████▄   ▄████████ 
    ███▀▀▀██▄ ███   ▀███ ███    ███ ███    ███ 
    ███   ███ ███    ███ ███    ███ ███    █▀  
    ███   ███ ███    ███ ███    ███ ███        
    ███   ███ ███    ███ ███    ███ ███        
    ███   ███ ███    ███ ███    ███ ███    █▄  
    ███   ███ ███   ▄███ ███    ███ ███    ███ 
    ▀█   █▀  ████████▀   ▀██████▀  ████████▀  
                                                            
           NDoc - Nmap Documentation
""")

time.sleep(2.5)

# Read targets and VLAN IDs
with open('targets.txt', 'r') as targets_file:
    targets = []
    vlanIDs = []
    for line in targets_file:
        line = line.strip()
        if line and "," in line:
            ip, vlan = line.split(",")
            targets.append(ip.strip())
            vlanIDs.append(vlan.strip())

# Go through each VLAN and parse XMLs

for target, vlanID in zip(targets, vlanIDs):
    time.sleep(0.025)
    print(f"\n=== Processing VLAN {vlanID} ===")
    md_lines = []
    # Header for VLAN
    md_lines.append(f"# Scan Results: VLAN {vlanID}\n")
    try:
        print(f"Parsing result_VLAN{vlanID}/result.xml ...")
        tree = ET.parse(f"result_VLAN{vlanID}/result.xml")
        root = tree.getroot()
        print(f"Parsed result.xml for VLAN {vlanID}.")
    except FileNotFoundError:
        print(f"[!] File not found: result_VLAN{vlanID}/result.xml")
        continue
    except ET.ParseError as e:
        print(f"[!] XML error in VLAN {vlanID}: {e}")
        continue

    # Go through hosts in the result.xml
    for host in root.findall("host"):
        print("\n--- New Host ---")
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            address = host.find("address")
            if address is not None:
                ip_addr = address.get("addr")

                print(f"Host: {ip_addr} is up.")

                # Find open ports and collect info for markdown
                open_ports_info = []
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        service = port.find("service")
                        name = service.get("name") if service is not None else ""
                        product = service.get("product") if service is not None else ""
                        version = service.get("version") if service is not None else ""
                        protocol = port.get("protocol")
                        portid = port.get("portid")
                        print(f"  Open port: {portid}/{protocol} - {name} {product} {version}")
                        open_ports_info.append({
                            "portid": portid,
                            "protocol": protocol,
                            "name": name,
                            "product": product,
                            "version": version
                        })

                # Markdown: Host section
                md_lines.append(f"## Host: `{ip_addr}`  \n**Status:** 🟢 up\n\n---\n")
                md_lines.append("### Open Ports\n")
                md_lines.append("| Port | Protocol | Service | Product | Version |")
                md_lines.append("|------|----------|---------|---------|---------|")
                for port in open_ports_info:
                    md_lines.append(f"| {port['portid']} | {port['protocol']} | {port['name']} | {port['product']} | {port['version']} |")
                md_lines.append("\n---\n")

                # Vulnerabilities section
                md_lines.append("### Vulnerabilities\n")

                if open_ports_info:
                    ip_no_cidr = ip_addr.split("/")[0]
                    safe_ip = ip_no_cidr.replace(".", "_")

                    try:
                        print(f"  Parsing vulncheck: result_VLAN{vlanID}/{safe_ip}/{safe_ip}_vulncheck.xml ...")
                        tree2 = ET.parse(f"result_VLAN{vlanID}/{safe_ip}/{safe_ip}_vulncheck.xml")
                        root2 = tree2.getroot()
                        print(f"  Parsed vulncheck for {safe_ip} in VLAN {vlanID}.")
                    except FileNotFoundError:
                        print(f"  [!] No vulncheck file for {safe_ip}")
                        continue
                    except ET.ParseError as e:
                        print(f"  [!] XML error in vulncheck for {safe_ip}: {e}")
                        continue

                    for port in open_ports_info:
                        portid = port['portid']
                        protocol = port['protocol']
                        print(f"    Checking vulnerabilities for port {portid}/{protocol} ...")
                        vuln_port = root2.find(f".//port[@portid='{portid}'][@protocol='{protocol}']")
                        if vuln_port is None:
                            print(f"      No vuln data for port {portid}/{protocol}.")
                            continue
                        script = vuln_port.find("script[@id='vulners']")
                        if script is None:
                            print(f"      No vulners script for port {portid}/{protocol}.")
                            continue
                        output = script.get("output")
                        print(f"      Vulners script output: {output}")
                        md_lines.append(f"#### {protocol} {portid} - {port['name']} ({port['product']} {port['version']})\n")
                        md_lines.append(f"- **State:** open")

                        # Get total CVEs
                        total = "0"
                        table_vulners = script.find("table[@key='vulners']")
                        if table_vulners is not None:
                            total_elem = table_vulners.find("elem[@key='total']")
                            if total_elem is not None and total_elem.text:
                                total = total_elem.text
                        print(f"      Total CVEs: {total}")
                        md_lines.append(f"- **Total CVEs:** {total}\n")

                        # Markdown table header for CVEs
                        md_lines.append("| CVE ID | Title | Description | Product | Score | Link(s) |")
                        md_lines.append("|--------|-------|-------------|---------|-------|------|")

                        # For each vuln table (vuln_0, vuln_1, ...)
                        if table_vulners is not None:
                            for vuln_table in table_vulners.findall("table"):
                                vuln = {}
                                for elem in vuln_table.findall("elem"):
                                    k = elem.get("key")
                                    v = elem.text if elem.text else ""
                                    vuln[k] = v
                                # CVSS score
                                score = ""
                                cvss_elem = vuln_table.find("elem[@key='cvss']/table/elem[@key='score']")
                                if cvss_elem is not None and cvss_elem.text:
                                    score = cvss_elem.text
                                # CVE reference links (all, comma-separated)
                                cve_links = []
                                references_parent = vuln_table.find("elem[@key='references']/table")
                                if references_parent is not None:
                                    for ref_elem in references_parent.findall("elem"):
                                        if ref_elem.text:
                                            cve_links.append(ref_elem.text)
                                cve_links_md = ", ".join(cve_links)
                                if 'id' in vuln:
                                    print(f"        CVE: {vuln.get('id','')} | Links: {cve_links_md}")
                                    md_lines.append(f"| {vuln.get('id','')} | {vuln.get('title','')} | {vuln.get('description','')} | {vuln.get('product','')} | {score} | {cve_links_md} |")
                        md_lines.append("\n---\n")

    print(f"Writing markdown report to result_VLAN{vlanID}/docs.md ...")
    with open(f"result_VLAN{vlanID}/docs.md", "w") as f:
        f.write("\n".join(md_lines))
    print(f"Done with VLAN {vlanID}.\n")
