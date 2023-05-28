import xml.etree.ElementTree as etree
import time
import argparse


# vars
skipped_findings = [
    "Nessus Scan Information",
    "Traceroute Information",
    "Common Platform Enumeration (CPE)",
    "ICMP Timestamp Request Remote Date Disclosure",
    "OS Identification Failed",
    "Open Port Re-check",
    "Do not scan printers",
    "ICMP Timestamp Request Remote Date Disclosure",
    "Device Type",
    "Service Detection (GET request)"
    ]
hosts = []
vulns = []
ultimate_dictionary = {}

# colours
RST = '\033[39m'
CYAN = '\033[1;36m'
GREY = '\033[1;30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'

# args
arg_parser = argparse.ArgumentParser(description='Make nessus vulns go into a file all neat etc')
arg_parser.add_argument('-n', '--ness', required=True, help='Name of exported nessus file')
arg_parser.add_argument('-o', '--output', required=True, help='Output file')
arg_parser.add_argument('-i', '--info', help='Include INFO items', action='store_true')
args = arg_parser.parse_args()
nessus_file = args.ness
output_file = args.output


def banner():

    print("""
         __   __  _______  ___      __   __         __    _  _______  _______  _______  __   __  _______ 
        |  | |  ||       ||   |    |  | |  |       |  |  | ||       ||       ||       ||  | |  ||       |
        |  | |  ||    ___||   |    |  |_|  | ____  |   |_| ||    ___||  _____||  _____||  | |  ||  _____|
        |  |_|  ||   | __ |   |    |       ||____| |       ||   |___ | |_____ | |_____ |  |_|  || |_____ 
        |       ||   ||  ||   |___ |_     _|       |  _    ||    ___||_____  ||_____  ||       ||_____  |
        |       ||   |_| ||       |  |   |         | | |   ||   |___  _____| | _____| ||       | _____| |
        |_______||_______||_______|  |___|         |_|  |__||_______||_______||_______||_______||_______|
        v1.0
        """)

    time.sleep(1)


def get_all_vulns(nessus_file):

    tree = etree.parse(nessus_file)
    root = tree.getroot()
    print(f"[INF] Finding all vulnerabilites in report...")
    # loop through all hosts in report
    host_length = len(root[1])
    for x in range(0, host_length):

        host_name = root[1][x].attrib["name"]
        # print(f"[DBG] Checking {RED}{host_name}{RST}")
        # this will get the plugin names for that host
        for y in range(0, len(root[1][x])):

            try:
                vuln_severity = root[1][x][y].attrib["severity"]
                vuln_name = root[1][x][y].attrib["pluginName"]
                vuln_port = root[1][x][y].attrib["port"]
                # print("")
                # print(f"[DBG] Found: {vuln_name} on port {vuln_port}")
                # print(f"[DBG] Vuln severity: {vuln_severity}")
                # if args.info is true, add in all the info findings
                if vuln_severity == "0":
                    if args.info:
                        vuln_severity = "5 - Info"
                    else:
                        continue
                if vuln_severity == "1":
                    vuln_severity = "4 - Low"
                if vuln_severity == "2":
                    vuln_severity = "3 - Medium"
                if vuln_severity == "3":
                    vuln_severity = "2 - High"
                if vuln_severity == "4":
                    vuln_severity = "1 - Critical"
                vuln_name = "[" + vuln_severity + "] " + vuln_name
                vulns.append(vuln_name + ":" + vuln_port)
                # if its not already in there or in our skip list, add it
                if vuln_name not in skipped_findings and vuln_name not in vulns:
                    # print(f"[DBG] {vuln_name} ADDING")
                    # print(f"[DBG] Adding to dictionary")
                    # create empty entry for that vuln in the dictionary
                    try:
                        ultimate_dictionary[vuln_name].append(host_name + ":" + vuln_port)
                    except:
                        ultimate_dictionary[vuln_name] = []
                        ultimate_dictionary[vuln_name].append(host_name + ":" + vuln_port)


                else:
                    # print(f"[DBG] SKIPPING {vuln_name}")
                    pass
            except:
                pass

    return ultimate_dictionary


def print_dict(dict_to_print):
    for a in sorted(dict_to_print.keys()):
        print(f"{a}:")
        for b in dict_to_print[a]:
            print(f"\t{GREY}{b}{RST}")


def write_dict(dict_to_print):
    print(f"\n[INF] Writing to {output_file}")
    with open(output_file, "w") as file:
        for a in sorted(dict_to_print.keys()):
            file.writelines(f"{a}:\n")
            for b in dict_to_print[a]:
                file.writelines(f"{b}\n")
            file.writelines("\n")
    print("[SUC] Done.")
    file.close()


banner()
finished_dict = get_all_vulns(nessus_file)
print_dict(finished_dict)
write_dict(finished_dict)
