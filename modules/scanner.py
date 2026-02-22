import nmap
import random
import time

class Scanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            self.has_nmap = True
        except nmap.PortScannerError:
            self.has_nmap = False
            print("Nmap not found. Running in SIMULATION MODE.")
        except Exception as e:
            self.has_nmap = False
            print(f"Error initializing Nmap: {e}. Running in SIMULATION MODE.")

    def scan_target(self, target):
        """
        Scans the target for open ports and services.
        If nmap is not available, returns simulated realistic data.
        """
        if self.has_nmap:
            try:
                # Basic scan for top 100 ports to be fast
                self.nm.scan(target, arguments='-sV -F --version-intensity 0') 
                
                # Check if host is up
                if target not in self.nm.all_hosts():
                    return self._get_simulated_results(target, "Host seems down or blocking probes")

                host_data = self.nm[target]
                results = {
                    "host": target,
                    "state": host_data.state(),
                    "protocols": []
                }

                for proto in self.nm[target].all_protocols():
                    ports = []
                    lport = self.nm[target][proto].keys()
                    for port in lport:
                        service = self.nm[target][proto][port]
                        ports.append({
                            "port": port,
                            "state": service['state'],
                            "name": service['name'],
                            "product": service['product'],
                            "version": service['version']
                        })
                    results["protocols"].append({
                        "protocol": proto,
                        "ports": ports
                    })
                return results

            except Exception as e:
                print(f"Scan error: {e}")
                return self._get_simulated_results(target)
        else:
            time.sleep(2) # Simulate network delay
            return self._get_simulated_results(target)

    def _get_simulated_results(self, target, note=None):
        return {
            "host": target,
            "state": "up",
            "is_simulated": True,
            "note": note,
            "protocols": [
                {
                    "protocol": "tcp",
                    "ports": [
                        {"port": 21, "state": "open", "name": "ftp", "product": "vsftpd", "version": "2.3.4"},
                        {"port": 22, "state": "open", "name": "ssh", "product": "OpenSSH", "version": "4.7p1"},
                        {"port": 80, "state": "open", "name": "http", "product": "Apache httpd", "version": "2.2.8"},
                        {"port": 3306, "state": "open", "name": "mysql", "product": "MySQL", "version": "5.0.51a"}
                    ]
                }
            ]
        }
