#!/usr/bin/env python3
"""Network utilities for Kali Server."""

import socket
import subprocess
import ipaddress
import json
from core.config import logger


def get_network_info():
    """Get comprehensive network information for the Kali Linux system."""
    network_info = {
        "interfaces": [],
        "recommended_ip": None,
        "pentest_suitable_ips": [],
        "test_suitable_ips": [],
        "success": True
    }
    
    try:
        # Method 1: Get all network interfaces with detailed info
        try:
            result = subprocess.run(['ip', '-j', 'addr', 'show'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                interfaces_data = json.loads(result.stdout)
                
                for interface in interfaces_data:
                    interface_name = interface.get('ifname', 'unknown')
                    interface_state = interface.get('operstate', 'unknown')
                    
                    # Process each IP address on this interface
                    for addr_info in interface.get('addr_info', []):
                        if addr_info.get('family') == 'inet':  # IPv4 only
                            ip_address = addr_info.get('local')
                            if ip_address:
                                interface_info = {
                                    "interface": interface_name,
                                    "ip": ip_address,
                                    "state": interface_state,
                                    "scope": addr_info.get('scope', 'unknown'),
                                    "is_loopback": interface_name == 'lo',
                                    "is_docker_bridge": interface_name == 'docker0' or 'docker' in interface_name.lower(),
                                    "is_vpn_tunnel": interface_name.startswith('tun') or interface_name.startswith('tap'),
                                    "is_private": _is_private_ip(ip_address),
                                    "is_pentest_suitable": _is_suitable_for_pentest(interface_name, ip_address, interface_state),
                                    "is_test_suitable": _is_suitable_for_local_tests(interface_name, ip_address, interface_state)
                                }
                                network_info["interfaces"].append(interface_info)
        except Exception as e:
            logger.error(f"Could not parse ip command output: {e}")
        
        # Method 2: Fallback - get primary IP via socket connection
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                primary_ip = s.getsockname()[0]
                
                # Add primary IP if not already found
                if not any(iface["ip"] == primary_ip for iface in network_info["interfaces"]):
                    network_info["interfaces"].append({
                        "interface": "primary_detected",
                        "ip": primary_ip,
                        "state": "UP",
                        "scope": "global",
                        "is_loopback": primary_ip.startswith('127.'),
                        "is_docker_bridge": False,
                        "is_vpn_tunnel": False,
                        "is_private": _is_private_ip(primary_ip),
                        "is_pentest_suitable": not primary_ip.startswith('127.'),
                        "is_test_suitable": True
                    })
        except Exception as e:
            logger.warning(f"Could not determine primary IP: {e}")
        
        # Determine recommended IPs and suitable IPs
        network_info["recommended_ip"] = _select_best_ip_for_pentest(network_info["interfaces"])
        network_info["pentest_suitable_ips"] = [
            {"interface": iface["interface"], "ip": iface["ip"]} 
            for iface in network_info["interfaces"] 
            if iface.get("is_pentest_suitable", False)
        ]
        network_info["test_suitable_ips"] = [
            {"interface": iface["interface"], "ip": iface["ip"]} 
            for iface in network_info["interfaces"] 
            if iface.get("is_test_suitable", False)
        ]
        
        return network_info
        
    except Exception as e:
        logger.error(f"Error getting network info: {str(e)}")
        network_info["success"] = False
        network_info["error"] = str(e)
        return network_info


def _is_private_ip(ip_str):
    """Check if IP address is in private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False


def _is_suitable_for_pentest(interface_name, ip_address, interface_state):
    """Determine if an IP address is suitable for real pentesting scenarios."""
    # Skip if interface is down
    if interface_state not in ['UP', 'LOWER_UP', 'UNKNOWN']:
        return False
    
    # Skip loopback interfaces (not useful for pentest) - but only for 127.x.x.x addresses
    if interface_name == 'lo' and ip_address.startswith('127.'):
        return False
    
    # Skip Docker bridge (only for local container communication)
    if interface_name == 'docker0':
        return False
    
    # Skip point-to-point interfaces that are down
    if interface_name.startswith('pivot') and interface_state in ['DOWN', 'NO-CARRIER']:
        return False
    
    # VPN tunnels are EXCELLENT for pentest - prioritize them
    if (interface_name.startswith('tun') or interface_name.startswith('tap')):
        return True
    
    # Main ethernet interface is good for pentest
    if interface_name.startswith('eth') and interface_state in ['UP', 'LOWER_UP']:
        return True
    
    # Any other UP interface with valid non-127 IP (including lo with non-127 IPs like 10.255.255.254)
    if interface_state in ['UP', 'LOWER_UP'] and not ip_address.startswith('127.'):
        return True
    
    return False


def _is_suitable_for_local_tests(interface_name, ip_address, interface_state):
    """Determine if an IP address is suitable for local reverse shell tests."""
    # Skip if interface is down
    if interface_state not in ['UP', 'LOWER_UP', 'UNKNOWN']:
        return False
    
    # Skip loopback interfaces (Docker containers can't connect to host loopback) - but only 127.x.x.x
    if interface_name == 'lo' and ip_address.startswith('127.'):
        return False
    
    # Skip point-to-point interfaces that are down
    if interface_name.startswith('pivot') and interface_state in ['DOWN', 'NO-CARRIER']:
        return False
    
    # Docker bridge is excellent for local container communication
    if interface_name == 'docker0':
        return True
    
    # Main ethernet interface is good for local tests
    if interface_name.startswith('eth') and interface_state in ['UP', 'LOWER_UP']:
        return True
    
    # VPN tunnels can work for local tests if up
    if (interface_name.startswith('tun') or interface_name.startswith('tap')):
        return True
    
    # Any other UP interface with valid non-127 IP
    if interface_state in ['UP', 'LOWER_UP'] and not ip_address.startswith('127.'):
        return True
    
    return False


def _select_best_ip_for_pentest(interfaces):
    """Select the best IP address for pentesting scenarios."""
    if not interfaces:
        return "127.0.0.1"
    
    # Priority 1: VPN tunnel interfaces (best for pentest) - HIGHEST PRIORITY
    vpn_candidates = [
        iface for iface in interfaces
        if (iface.get("is_vpn_tunnel", False) and 
            iface.get("is_pentest_suitable", False))
    ]
    if vpn_candidates:
        # Sort by interface name to get tun0 before tun1, etc.
        vpn_candidates.sort(key=lambda x: x["interface"])
        return vpn_candidates[0]["ip"]
    
    # Priority 2: Main ethernet interface
    eth_candidates = [
        iface for iface in interfaces
        if (iface["interface"].startswith("eth") and 
            iface.get("is_pentest_suitable", False))
    ]
    if eth_candidates:
        return eth_candidates[0]["ip"]
    
    # Priority 3: Any suitable interface for pentest
    pentest_candidates = [
        iface for iface in interfaces
        if iface.get("is_pentest_suitable", False)
    ]
    if pentest_candidates:
        return pentest_candidates[0]["ip"]
    
    # Fallback: any UP interface that's not loopback
    up_candidates = [
        iface for iface in interfaces
        if (iface.get("state") in ["UP", "LOWER_UP"] and 
            not iface.get("is_loopback", False))
    ]
    if up_candidates:
        return up_candidates[0]["ip"]
    
    # Last resort: first available IP
    return interfaces[0]["ip"] if interfaces else "127.0.0.1"


def select_best_ip_for_local_tests(interfaces):
    """Select the best IP address for local testing scenarios."""
    if not interfaces:
        return "127.0.0.1"
    
    # Priority 1: Docker bridge (best for local container communication)
    docker_candidates = [
        iface for iface in interfaces
        if (iface.get("is_docker_bridge", False) and 
            iface.get("is_test_suitable", False))
    ]
    if docker_candidates:
        return docker_candidates[0]["ip"]
    
    # Priority 2: Main ethernet interface
    eth_candidates = [
        iface for iface in interfaces
        if (iface["interface"].startswith("eth") and 
            iface.get("is_test_suitable", False))
    ]
    if eth_candidates:
        return eth_candidates[0]["ip"]
    
    # Priority 3: Any suitable interface for local tests
    test_candidates = [
        iface for iface in interfaces
        if iface.get("is_test_suitable", False)
    ]
    if test_candidates:
        return test_candidates[0]["ip"]
    
    # Fallback: any UP interface that's not loopback and not 127.x.x.x
    up_candidates = [
        iface for iface in interfaces
        if (iface.get("state") in ["UP", "LOWER_UP"] and 
            not iface.get("is_loopback", False) and
            not iface["ip"].startswith("127."))
    ]
    if up_candidates:
        return up_candidates[0]["ip"]
    
    # Last resort: any non-loopback IP
    non_loopback_candidates = [
        iface for iface in interfaces
        if (not iface.get("is_loopback", False) and
            not iface["ip"].startswith("127."))
    ]
    if non_loopback_candidates:
        return non_loopback_candidates[0]["ip"]
    
    # Absolute last resort: 127.0.0.1 (should not happen)
    return "127.0.0.1"
