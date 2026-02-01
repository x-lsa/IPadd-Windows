import sys
import subprocess
import re
import ctypes
import json

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_ps(cmd):
    """Executes a PowerShell command and returns (success, output)."""
    full_cmd = ['powershell', '-NoProfile', '-Command', cmd]
    res = subprocess.run(full_cmd, capture_output=True, text=True)
    return res.returncode == 0, (res.stdout + res.stderr).strip()

def run_ps_json(cmd):
    """Executes PowerShell and returns parsed JSON."""
    full_cmd = ['powershell', '-NoProfile', '-Command', f"{cmd} | ConvertTo-Json -Depth 1 -Compress"]
    res = subprocess.run(full_cmd, capture_output=True, text=True)
    if not res.stdout.strip(): return None
    try:
        data = json.loads(res.stdout)
        return [data] if isinstance(data, dict) else data
    except: return None

def run_netsh(args):
    """Executes netsh for IP addition logic."""
    full_cmd = ['netsh'] + args
    res = subprocess.run(full_cmd, capture_output=True, text=True)
    return res.returncode == 0, (res.stdout + res.stderr).strip()

def is_dhcp_enabled(interface):
    _, output = run_netsh(['interface', 'ipv4', 'show', 'address', f'name="{interface}"'])
    return "DHCP enabled:                         Yes" in output or "DHCP enabled: Yes" in output

def get_target_interface():
    # Hardcoded as requested, but logic is here if it ever moves back to 'Ethernet 17'
    return "Ethernet"

def print_help():
    print("\n--- IPADD Utility Help ---")
    print("  ipadd list             : Dashboard showing IPs, VLAN ID, and Hardware.")
    print("  ipadd clear            : Force-reset to DHCP and remove VLAN tags.")
    print("  ipadd vlan [ID]        : Force a VLAN tag (e.g., ipadd vlan 100).")
    print("  ipadd vlan clear       : Set VLAN back to 0 (Untagged).")
    print("  ipadd [IP]/[CIDR]      : Add/Set a static IP (e.g., 10.0.0.5/24).")
    print("  ipadd help             : Show this menu.\n")

def cmd_list(interface):
    print(f"\n{'='*65}")
    print(f" INTERFACE STATUS: {interface.upper()}")
    print(f"{'='*65}")

    # 1. Get Hardware Info (same as before)
    hw_cmd = f"Get-NetAdapter -Name '{interface}' | Select-Object Status, LinkSpeed, MacAddress, DriverDescription"
    hw_data = run_ps_json(hw_cmd)
    
    # 2. Get VLAN ID
    vlan_cmd = f"Get-NetAdapterAdvancedProperty -Name '{interface}' -DisplayName 'VLAN ID' | Select-Object -ExpandProperty DisplayValue"
    _, vlan_id = run_ps(vlan_cmd)
    vlan_id = vlan_id if vlan_id else "0"

    if hw_data:
        hw = hw_data[0]
        print(f" {'Hardware':<15} : {hw.get('DriverDescription')}")
        print(f" {'MAC Address':<15} : {hw.get('MacAddress')}")
        print(f" {'Link Status':<15} : {hw.get('Status')} @ {hw.get('LinkSpeed')}")
        print(f" {'VLAN ID':<15} : {vlan_id}")
    
    print(f"{'-'*65}")

    # 3. Get IP Addresses with FILTER for 169.254
    ip_cmd = f"Get-NetIPAddress -InterfaceAlias '{interface}' -AddressFamily IPv4 | Select-Object IPAddress, PrefixLength"
    ip_data = run_ps_json(ip_cmd)

    print(f" {'IP Address':<20} | {'CIDR':<6} | {'Subnet Mask'}")
    print(f" {'-'*20}-+-{'-'*6}-+-{'-'*18}")

    found_valid_ip = False
    if ip_data:
        for entry in ip_data:
            ip = entry.get('IPAddress')
            
            # --- THE FILTER ---
            if ip.startswith("169.254"):
                continue # Skip this address entirely
            
            cidr = entry.get('PrefixLength')
            mask_bits = (0xffffffff >> (32 - cidr)) << (32 - cidr)
            mask = f"{(mask_bits >> 24) & 0xff}.{(mask_bits >> 16) & 0xff}.{(mask_bits >> 8) & 0xff}.{mask_bits & 0xff}"
            
            print(f" {ip:<20} | /{cidr:<5} | {mask}")
            found_valid_ip = True

    if not found_valid_ip:
        # If the only IP was 169 (or nothing was there), show a clean status
        if is_dhcp_enabled(interface):
            print(" (DHCP Active - Searching for Router / No Cable)")
        else:
            print(" (No IPv4 addresses found)")
            
    print(f"{'='*65}\n")

def main():
    if not is_admin():
        print("!! ERROR: Please run as ADMINISTRATOR !!")
        return

    interface = get_target_interface()
    args = sys.argv[1:] if len(sys.argv) > 1 else [input(f"[{interface}] Command: ").strip().lower()]
    val = args[0].lower()

    if val == "help":
        print_help()

    elif val == "list":
        cmd_list(interface)

    elif val == "vlan":
        if len(args) < 2:
            print("Usage: ipadd vlan [ID] | ipadd vlan clear")
            return
        v_id = "0" if args[1] == "clear" else args[1]
        print(f"Updating Driver Property 'VLAN ID' to {v_id}...")
        success, _ = run_ps(f"Set-NetAdapterAdvancedProperty -Name '{interface}' -DisplayName 'VLAN ID' -DisplayValue '{v_id}'")
        if success:
            print(f"SUCCESS!")
        else:
            print("ERROR: Could not set Advanced Property. Check property name in Device Manager.")

    elif val == "clear":
        print(f"Resetting {interface} (IPs and VLAN)...")
        run_ps(f"Set-NetAdapterAdvancedProperty -Name '{interface}' -DisplayName 'VLAN ID' -DisplayValue '0'")
        run_ps(f"Remove-NetIPAddress -InterfaceAlias '{interface}' -AddressFamily IPv4 -Confirm:$false")
        run_ps(f"Set-NetIPInterface -InterfaceAlias '{interface}' -Dhcp Enabled")
        print("SUCCESS!")

    elif "/" in val:
        match = re.match(r'^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$', val)
        if match:
            ip, cidr = match.group(1), int(match.group(3))
            mask_bits = (0xffffffff >> (32 - cidr)) << (32 - cidr)
            mask = f"{(mask_bits >> 24) & 0xff}.{(mask_bits >> 16) & 0xff}.{(mask_bits >> 8) & 0xff}.{mask_bits & 0xff}"
            
            if is_dhcp_enabled(interface):
                run_netsh(['interface', 'ipv4', 'set', 'address', f'name="{interface}"', 'static', ip, mask])
            else:
                run_netsh(['interface', 'ipv4', 'add', 'address', f'name="{interface}"', ip, mask])
            print(f"SUCCESS!")

if __name__ == "__main__":
    main()