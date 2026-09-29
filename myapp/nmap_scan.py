import nmap


NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"

SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    4444: "Common testing/backdoor port",
}


def run_nmap_scan(target_host):

    target_host = target_host.strip()

    if not target_host:
        return "Target host cannot be empty.", "Failed"

    try:

        # Tell python-nmap exactly where nmap.exe is installed
        scanner = nmap.PortScanner(
            nmap_search_path=(NMAP_PATH,)
        )

        scanner.scan(
            hosts=target_host,
            arguments="-sV"
        )

        if target_host not in scanner.all_hosts():
            return (
                f"No scan information found for target: {target_host}",
                "Failed"
            )

        result_lines = []

        result_lines.append(
            f"Target Host: {target_host}"
        )

        result_lines.append(
            f"Host State: {scanner[target_host].state()}"
        )

        result_lines.append("")

        suspicious_found = False

        for protocol in scanner[target_host].all_protocols():

            result_lines.append(
                f"Protocol: {protocol.upper()}"
            )

            result_lines.append("-" * 80)

            ports = scanner[target_host][protocol].keys()

            for port in sorted(ports):

                port_info = scanner[target_host][protocol][port]

                state = port_info.get(
                    "state",
                    "unknown"
                )

                service = port_info.get(
                    "name",
                    "unknown"
                )

                product = port_info.get(
                    "product",
                    ""
                )

                version = port_info.get(
                    "version",
                    ""
                )

                if port in SUSPICIOUS_PORTS:

                    suspicious_found = True

                    flag = (
                        f"SUSPICIOUS - "
                        f"{SUSPICIOUS_PORTS[port]}"
                    )

                else:

                    flag = "Normal"

                result_lines.append(
                    f"Port: {port} | "
                    f"State: {state} | "
                    f"Service: {service} | "
                    f"Product: {product} | "
                    f"Version: {version} | "
                    f"Status: {flag}"
                )

        if suspicious_found:

            status = "Suspicious"

        else:

            status = "Completed"

        scanresult = "\n".join(result_lines)

        return scanresult, status

    except nmap.PortScannerError as e:

        return (
            f"Nmap error: {str(e)}",
            "Failed"
        )

    except Exception as e:

        return (
            f"Unexpected error: {str(e)}",
            "Failed"
        )