import unittest
import logging
from unittest.mock import patch, MagicMock
from dragonshard.recon.scanner import run_scan, get_open_ports, scan_common_services

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TestScanner(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        logger.info("Setting up test fixtures")
        self.test_target = "127.0.0.1"
        self.mock_nmap_data = {
            "127.0.0.1": {
                "state": "up",
                "tcp": {
                    22: {
                        "state": "open",
                        "name": "ssh",
                        "version": "OpenSSH 8.2p1",
                        "product": "OpenSSH",
                        "extrainfo": "Ubuntu 4ubuntu0.2"
                    },
                    80: {
                        "state": "open",
                        "name": "http",
                        "version": "nginx 1.18.0",
                        "product": "nginx",
                        "extrainfo": ""
                    }
                },
                "udp": {
                    53: {
                        "state": "open",
                        "name": "domain",
                        "version": "BIND 9.16.1",
                        "product": "BIND",
                        "extrainfo": ""
                    }
                }
            }
        }
        logger.debug(f"Mock data set up: {self.mock_nmap_data}")

    @patch('dragonshard.recon.scanner.nmap.PortScanner')
    def test_run_scan_comprehensive(self, mock_scanner_class):
        """Test comprehensive scan functionality."""
        logger.info("Starting test_run_scan_comprehensive")
        
        # Mock the nmap scanner
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.all_hosts.return_value = ["127.0.0.1"]
        
        # Create a proper mock host object that has a state() method
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        
        # Create the data structure that the scanner expects
        tcp_data = {
            22: {
                "state": "open",
                "name": "ssh",
                "version": "OpenSSH 8.2p1",
                "product": "OpenSSH",
                "extrainfo": "Ubuntu 4ubuntu0.2"
            },
            80: {
                "state": "open",
                "name": "http",
                "version": "nginx 1.18.0",
                "product": "nginx",
                "extrainfo": ""
            }
        }
        
        udp_data = {
            53: {
                "state": "open",
                "name": "domain",
                "version": "BIND 9.16.1",
                "product": "BIND",
                "extrainfo": ""
            }
        }
        
        # Set up the mock to return the correct data structure
        mock_host.__getitem__.side_effect = lambda x: {
            "tcp": tcp_data,
            "udp": udp_data
        }[x]
        
        # Make the mock support 'in' operator for tcp and udp
        mock_host.__contains__.side_effect = lambda x: x in ["tcp", "udp"]
        
        mock_host.all_tcp.return_value = [22, 80]
        mock_host.all_udp.return_value = [53]
        
        mock_scanner.__getitem__.return_value = mock_host
        
        logger.debug("Mock scanner set up, calling run_scan")
        result = run_scan(self.test_target, "comprehensive")
        logger.debug(f"Scan result: {result}")
        
        # Verify the scan was called with correct arguments
        mock_scanner.scan.assert_called_once_with(
            hosts=self.test_target, 
            arguments='-T4 -sS -sU -p- --version-intensity 5'
        )
        
        # Verify the result structure
        self.assertIn("127.0.0.1", result)
        self.assertEqual(result["127.0.0.1"]["status"], "up")
        self.assertIn("tcp", result["127.0.0.1"])
        self.assertIn("udp", result["127.0.0.1"])
        
        # Check TCP ports
        tcp_ports = result["127.0.0.1"]["tcp"]
        self.assertIn(22, tcp_ports)
        self.assertEqual(tcp_ports[22]["service"], "ssh")
        self.assertEqual(tcp_ports[22]["product"], "OpenSSH")
        
        # Check UDP ports
        udp_ports = result["127.0.0.1"]["udp"]
        self.assertIn(53, udp_ports)
        self.assertEqual(udp_ports[53]["service"], "domain")
        
        logger.info("test_run_scan_comprehensive completed successfully")

    @patch('dragonshard.recon.scanner.nmap.PortScanner')
    def test_run_scan_quick(self, mock_scanner_class):
        """Test quick scan functionality."""
        logger.info("Starting test_run_scan_quick")
        
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.all_hosts.return_value = ["127.0.0.1"]
        
        # Create a proper mock host object
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        
        # Create the data structure that the scanner expects
        tcp_data = {
            22: {
                "state": "open",
                "name": "ssh",
                "version": "OpenSSH 8.2p1",
                "product": "OpenSSH",
                "extrainfo": "Ubuntu 4ubuntu0.2"
            },
            80: {
                "state": "open",
                "name": "http",
                "version": "nginx 1.18.0",
                "product": "nginx",
                "extrainfo": ""
            }
        }
        
        udp_data = {
            53: {
                "state": "open",
                "name": "domain",
                "version": "BIND 9.16.1",
                "product": "BIND",
                "extrainfo": ""
            }
        }
        
        mock_host.__getitem__.side_effect = lambda x: {
            "tcp": tcp_data,
            "udp": udp_data
        }[x]
        
        # Make the mock support 'in' operator for tcp and udp
        mock_host.__contains__.side_effect = lambda x: x in ["tcp", "udp"]
        
        mock_host.all_tcp.return_value = [22, 80]
        mock_host.all_udp.return_value = [53]
        
        mock_scanner.__getitem__.return_value = mock_host
        
        logger.debug("Mock scanner set up, calling run_scan")
        result = run_scan(self.test_target, "quick")
        logger.debug(f"Quick scan result: {result}")
        
        # Verify quick scan arguments
        mock_scanner.scan.assert_called_once_with(
            hosts=self.test_target, 
            arguments='-T4 -F'
        )
        
        logger.info("test_run_scan_quick completed successfully")

    @patch('dragonshard.recon.scanner.nmap.PortScanner')
    def test_run_scan_udp(self, mock_scanner_class):
        """Test UDP scan functionality."""
        logger.info("Starting test_run_scan_udp")
        
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.all_hosts.return_value = ["127.0.0.1"]
        
        # Create a proper mock host object
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        
        # Create the data structure that the scanner expects
        tcp_data = {
            22: {
                "state": "open",
                "name": "ssh",
                "version": "OpenSSH 8.2p1",
                "product": "OpenSSH",
                "extrainfo": "Ubuntu 4ubuntu0.2"
            },
            80: {
                "state": "open",
                "name": "http",
                "version": "nginx 1.18.0",
                "product": "nginx",
                "extrainfo": ""
            }
        }
        
        udp_data = {
            53: {
                "state": "open",
                "name": "domain",
                "version": "BIND 9.16.1",
                "product": "BIND",
                "extrainfo": ""
            }
        }
        
        mock_host.__getitem__.side_effect = lambda x: {
            "tcp": tcp_data,
            "udp": udp_data
        }[x]
        
        # Make the mock support 'in' operator for tcp and udp
        mock_host.__contains__.side_effect = lambda x: x in ["tcp", "udp"]
        
        mock_host.all_tcp.return_value = [22, 80]
        mock_host.all_udp.return_value = [53]
        
        mock_scanner.__getitem__.return_value = mock_host
        
        logger.debug("Mock scanner set up, calling run_scan")
        result = run_scan(self.test_target, "udp")
        logger.debug(f"UDP scan result: {result}")
        
        # Verify UDP scan arguments
        mock_scanner.scan.assert_called_once_with(
            hosts=self.test_target, 
            arguments='-T4 -sU -F'
        )
        
        logger.info("test_run_scan_udp completed successfully")

    def test_get_open_ports(self):
        """Test extracting open ports from scan results."""
        logger.info("Starting test_get_open_ports")
        
        scan_results = {
            "127.0.0.1": {
                "status": "up",
                "tcp": {
                    22: {"state": "open", "service": "ssh", "version": "OpenSSH", "product": "OpenSSH"},
                    23: {"state": "closed", "service": "telnet", "version": "", "product": ""},
                    80: {"state": "open", "service": "http", "version": "nginx", "product": "nginx"}
                },
                "udp": {
                    53: {"state": "open", "service": "domain", "version": "BIND", "product": "BIND"},
                    67: {"state": "closed", "service": "dhcps", "version": "", "product": ""}
                }
            }
        }
        
        logger.debug(f"Input scan results: {scan_results}")
        open_ports = get_open_ports(scan_results)
        logger.debug(f"Extracted open ports: {open_ports}")
        
        # Check structure
        self.assertIn("127.0.0.1", open_ports)
        self.assertIn("tcp", open_ports["127.0.0.1"])
        self.assertIn("udp", open_ports["127.0.0.1"])
        
        # Check TCP open ports
        tcp_open = open_ports["127.0.0.1"]["tcp"]
        self.assertEqual(len(tcp_open), 2)  # ports 22 and 80 should be open
        
        # Verify port 22
        port_22 = next(p for p in tcp_open if p["port"] == 22)
        self.assertEqual(port_22["service"], "ssh")
        self.assertEqual(port_22["product"], "OpenSSH")
        
        # Check UDP open ports
        udp_open = open_ports["127.0.0.1"]["udp"]
        self.assertEqual(len(udp_open), 1)  # only port 53 should be open
        
        # Verify port 53
        port_53 = udp_open[0]
        self.assertEqual(port_53["port"], 53)
        self.assertEqual(port_53["service"], "domain")
        
        logger.info("test_get_open_ports completed successfully")

    @patch('dragonshard.recon.scanner.nmap.PortScanner')
    def test_scan_common_services(self, mock_scanner_class):
        """Test scanning common services."""
        logger.info("Starting test_scan_common_services")
        
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.all_hosts.return_value = ["127.0.0.1"]
        
        # Create a proper mock host object
        mock_host = MagicMock()
        mock_host.state.return_value = "up"
        
        # Create the data structure that the scanner expects
        tcp_data = {
            22: {
                "state": "open",
                "name": "ssh",
                "version": "OpenSSH 8.2p1",
                "product": "OpenSSH",
                "extrainfo": "Ubuntu 4ubuntu0.2"
            },
            80: {
                "state": "open",
                "name": "http",
                "version": "nginx 1.18.0",
                "product": "nginx",
                "extrainfo": ""
            }
        }
        
        mock_host.__getitem__.side_effect = lambda x: {
            "tcp": tcp_data
        }[x]
        
        # Make the mock support 'in' operator for tcp
        mock_host.__contains__.side_effect = lambda x: x in ["tcp"]
        
        mock_host.all_tcp.return_value = [22, 80]
        
        mock_scanner.__getitem__.return_value = mock_host
        
        logger.debug("Mock scanner set up, calling scan_common_services")
        result = scan_common_services(self.test_target)
        logger.debug(f"Common services scan result: {result}")
        
        # Verify scan was called with common ports
        mock_scanner.scan.assert_called_once_with(
            hosts=self.test_target,
            ports="21,22,23,25,53,80,110,143,443,993,995,3306,5432,6379,8080,8443",
            arguments='-T4 -sS -sV'
        )
        
        # Check result structure
        self.assertIn("127.0.0.1", result)
        self.assertEqual(result["127.0.0.1"]["status"], "up")
        self.assertIn("services", result["127.0.0.1"])
        
        # Check services
        services = result["127.0.0.1"]["services"]
        self.assertIn(22, services)
        self.assertEqual(services[22]["protocol"], "tcp")
        self.assertEqual(services[22]["service"], "ssh")
        
        logger.info("test_scan_common_services completed successfully")

    def test_get_open_ports_empty_results(self):
        """Test get_open_ports with empty scan results."""
        logger.info("Starting test_get_open_ports_empty_results")
        
        empty_results = {}
        open_ports = get_open_ports(empty_results)
        logger.debug(f"Empty results open ports: {open_ports}")
        self.assertEqual(open_ports, {})
        
        logger.info("test_get_open_ports_empty_results completed successfully")

    def test_get_open_ports_no_open_ports(self):
        """Test get_open_ports when no ports are open."""
        logger.info("Starting test_get_open_ports_no_open_ports")
        
        scan_results = {
            "127.0.0.1": {
                "status": "up",
                "tcp": {
                    22: {"state": "closed", "service": "ssh", "version": "", "product": ""}
                },
                "udp": {
                    53: {"state": "closed", "service": "domain", "version": "", "product": ""}
                }
            }
        }
        
        logger.debug(f"Scan results with no open ports: {scan_results}")
        open_ports = get_open_ports(scan_results)
        logger.debug(f"Extracted open ports: {open_ports}")
        
        # Should have empty lists for both TCP and UDP
        self.assertEqual(len(open_ports["127.0.0.1"]["tcp"]), 0)
        self.assertEqual(len(open_ports["127.0.0.1"]["udp"]), 0)
        
        logger.info("test_get_open_ports_no_open_ports completed successfully")


if __name__ == '__main__':
    unittest.main()