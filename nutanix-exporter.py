#!/usr/bin/env python3

import argparse
import json
import requests
import getpass
import os
import sys
import re
import shutil
from urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as ET
from xml.dom import minidom
import time

try:
    import paramiko
except ImportError:
    print("Error: The 'paramiko' library is required for the export functionality.")
    print("Please install it using: pip install paramiko")
    sys.exit(1)

try:
    from scp import SCPClient
except ImportError:
    print("Error: The 'scp' library is required for the export functionality.")
    print("Please install it using: pip install scp")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: The 'tqdm' library is required for the progress bar.")
    print("Please install it using: pip install tqdm")
    sys.exit(1)


# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NutanixExporter:
    """
    A class to export Nutanix AHV VMs to QCOW2 format using the v3 API.
    """

    def __init__(self, cluster_ip, username, password, debug=False):
        self.cluster_ip = cluster_ip
        self.username = username
        self.password = password
        self.base_url = f"https://{self.cluster_ip}:9440/api/nutanix/v3"
        self.session = self._create_session()
        self.debug = debug
        print(f"Debug mode is {'ON' if self.debug else 'OFF'}")
        
        self.progress_bars = {}

        if self.debug:
            import logging
            paramiko_log_file = "paramiko_debug.log"
            print(f"Paramiko debug logging enabled. See {paramiko_log_file}")
            logging.basicConfig(filename=paramiko_log_file, level=logging.DEBUG)


    def _create_session(self):
        session = requests.Session()
        session.auth = (self.username, self.password)
        session.verify = False
        session.headers.update({'Content-Type': 'application/json; charset=utf-8'})
        return session

    def list_all_vms(self):
        print("Retrieving VM inventory...")
        endpoint = f"{self.base_url}/vms/list"
        payload = {"kind": "vm", "length": 500}
        try:
            response = self.session.post(endpoint, data=json.dumps(payload))
            response.raise_for_status()
            data = response.json()
            if data['metadata']['total_matches'] > 0:
                print("\n--- Available Virtual Machines ---")
                for vm in sorted(data['entities'], key=lambda x: x['spec']['name']):
                    print(f"  - Name: {vm['spec']['name']:<30} | UUID: {vm['metadata']['uuid']}")
                print("----------------------------------")
            else:
                print("No VMs found.")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while communicating with the Nutanix API: {e}")

    def get_vm_details(self, vm_name):
        print(f"Searching for VM '{vm_name}'...")
        endpoint = f"{self.base_url}/vms/list"
        payload = {"kind": "vm", "filter": f"vm_name=={vm_name}"}
        try:
            response = self.session.post(endpoint, data=json.dumps(payload))
            response.raise_for_status()
            data = response.json()
            if data['metadata']['total_matches'] == 0:
                print(f"Error: VM '{vm_name}' not found.")
                return None
            
            vm_uuid = data['entities'][0]['metadata']['uuid']
            print(f"Found VM '{vm_name}' with UUID: {vm_uuid}")
            print(f"Fetching details for VM UUID: {vm_uuid}...")
            
            detail_endpoint = f"{self.base_url}/vms/{vm_uuid}"
            response = self.session.get(detail_endpoint)
            response.raise_for_status()
            vm_details = response.json()

            if self.debug:
                print("\n--- DEBUG: Full VM Details API Response (v3) ---")
                print(json.dumps(vm_details, indent=2))
                print("------------------------------------------------\n")

            spec = vm_details.get('spec', {}).get('resources', {})
            status = vm_details.get('status', {}).get('resources', {})

            details = {
                'name': vm_details.get('spec', {}).get('name', 'N/A'),
                'uuid': vm_details.get('metadata', {}).get('uuid'),
                'vcpus': spec.get('num_vcpus_per_socket', 1) * spec.get('num_sockets', 1),
                'memory_mb': spec.get('memory_size_mib', 1024),
                'power_state': status.get('power_state', 'UNKNOWN'),
                'disks': []
            }

            for disk in spec.get('disk_list', []):
                device_props = disk.get('device_properties', {})
                if device_props.get('device_type') == 'DISK' and disk.get('uuid'):
                    # Capture disk size if available for space checks later
                    disk_size_mib = disk.get('disk_size_mib', 0)
                    details['disks'].append({
                        'uuid': disk['uuid'],
                        'size_mib': disk_size_mib
                    })
            
            print(f"Found {len(details['disks'])} exportable disk(s) for the VM.")
            return details

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while communicating with the Nutanix API: {e}")
            return None

    def _run_remote_command(self, ssh_client, command):
        if self.debug:
            print(f"--- DEBUG: Executing remote command ---\n{command}\n---------------------------------------")

        stdin, stdout, stderr = ssh_client.exec_command(command, get_pty=True)
        
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        exit_status = stdout.channel.recv_exit_status()
        
        if self.debug:
            print(f"--- DEBUG: Remote command results (Exit: {exit_status}) ---")
            if output: print(f"STDOUT:\n{output.strip()}")
            if error: print(f"STDERR:\n{error.strip()}")
            print("--------------------------------------------------")

        return output, error, exit_status
    
    def _connect_ssh(self, remotehost, remoteport, remoteusername, remotepassword):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh_client.connect(
            hostname=remotehost,
            port=remoteport, 
            username=remoteusername, 
            password=remotepassword, 
            timeout=15
        )
        
        # --- Tuning: Set keep-alive and optimize window size for performance ---
        transport = ssh_client.get_transport()
        if transport:
            transport.set_keepalive(60)
            # Increase window size to 4MB for better throughput
            transport.window_size = 4 * 1024 * 1024 
            # Reduce rekeying frequency (every 1TB)
            transport.packetizer.REKEY_BYTES = pow(2, 40)
            transport.packetizer.REKEY_PACKETS = pow(2, 40)
        
        return ssh_client

    def progress(self, filename, size, sent):
        filename_str = filename
        if filename_str not in self.progress_bars:
            self.progress_bars[filename_str] = tqdm(
              total=size, 
             unit='B', 
             unit_scale=True, 
              desc=f"Downloading {filename_str}"
          )
        progress_bar = self.progress_bars[filename_str]
        progress_bar.update(sent - progress_bar.n)

    def _download_scp(self, ssh, remote_path, local_path):
        try:
            with SCPClient(ssh.get_transport(), progress=self.progress) as scp:
                print(f"Downloading file {remote_path} to {local_path}...")
                scp.get(remote_path, local_path)
                
                for pbar in self.progress_bars.values():
                    pbar.close()

                print("File downloaded successfully!")

        except paramiko.AuthenticationException:
            print("Authentication failed.")
        except Exception as e:
            print(f"An error occurred during download: {e}")

    def check_cvm_space(self, ssh_client, work_dir, required_mib):
        """
        Checks if the CVM has enough space to perform the conversion.
        """
        print(f"Checking available disk space on CVM in {work_dir}...")
        
        # Get available space in MB from the specific path
        cmd = f"df -mP {work_dir} | awk 'NR==2 {{print $4}}'"
        output, error, status = self._run_remote_command(ssh_client, cmd)
        
        if status != 0:
            print(f"Warning: Could not check disk space ({error}). Proceeding with caution.")
            return

        try:
            available_mib = int(output.strip())
            
            # Safety buffer: Always leave at least 2GB free on the CVM to prevent crashes
            safety_buffer_mib = 2048 
            
            # Heuristic: We warn if available space is less than the PROVISIONED size of the disk.
            # QCOW2 is compressed, so it might fit, but it's risky.
            
            print(f"CVM Space: Available={available_mib}MB | Disk Size={required_mib}MB | Buffer={safety_buffer_mib}MB")

            if available_mib < safety_buffer_mib:
                raise Exception(f"CRITICAL: CVM is running out of space ({available_mib}MB free). Aborting to prevent crash.")

            if available_mib < (required_mib + safety_buffer_mib):
                print(f"\nWARNING: Available space ({available_mib}MB) is less than the provisioned disk size ({required_mib}MB).")
                print("If the disk is full or not compressible, the CVM storage might fill up and CRASH services.")
                print("Proceeding because QCOW2 compression usually saves space. Monitor closely.\n")
                time.sleep(3) # Give user a chance to read
            else:
                print("Disk space check passed.")

        except ValueError:
            print("Warning: Could not parse disk space output. Proceeding with caution.")

    def export_disk_to_qcow2(self, vm_details, disk_info, output_dir, cvm_user, cvm_pass):
        vm_name = vm_details['name']
        disk_uuid = disk_info['uuid']
        disk_size = disk_info.get('size_mib', 0)
        
        print(f"\n===== Starting export for disk {disk_uuid} =====")

        ssh_client = None
        remote_temp_dir = "export_temp"
        remote_qcow2_filename = f"export_{disk_uuid}.qcow2"
        remote_qcow2_path = f"{remote_temp_dir}/{remote_qcow2_filename}"

        try:
            print(f"Connecting to CVM {self.cluster_ip} via SSH...")
            ssh_client = self._connect_ssh(self.cluster_ip, 22, cvm_user, cvm_pass)

            # Create temp dir
            print(f"Creating remote temporary directory: {remote_temp_dir}")
            self._run_remote_command(ssh_client, f"mkdir -p {remote_temp_dir}")

            # --- Safety Check: Ensure CVM has space ---
            self.check_cvm_space(ssh_client, remote_temp_dir, disk_size)

            print("Discovering vdisk path via CVM (JSON mode)...")
            # --- Robustness: Use JSON output instead of regex ---
            acli_cmd = f"/usr/local/nutanix/bin/acli -o json vm.get '{vm_name}' include_vmdisk_paths=1"
            acli_output, acli_error, acli_status = self._run_remote_command(ssh_client, acli_cmd)

            if acli_status != 0:
                raise Exception(f"'acli vm.get' failed: {acli_error or acli_output}")

            source_vdisk_path_relative = None
            try:
                vm_data = json.loads(acli_output)
                # Helper to find disk in potentially nested structure
                # The output structure is usually { "VM_NAME": { "config": ... } }
                vm_config_root = next(iter(vm_data.values())) # Get the first value (the VM object)
                disk_list = vm_config_root.get('config', {}).get('disk_list', [])
                
                for disk in disk_list:
                    # Check both 'device_uuid' (top level) or nested in properties depending on version
                    curr_uuid = disk.get('device_uuid') or disk.get('uuid')
                    
                    if curr_uuid == disk_uuid:
                        source_vdisk_path_relative = disk.get('vmdisk_nfs_path')
                        break
            except json.JSONDecodeError:
                 raise Exception("Failed to parse acli JSON output.")

            if not source_vdisk_path_relative:
                raise Exception(f"Could not find 'vmdisk_nfs_path' for disk UUID {disk_uuid} in acli output.")

            source_vdisk_nfs_url = f"nfs://{self.cluster_ip}{source_vdisk_path_relative}"
            print(f"Constructed direct vdisk NFS URL: {source_vdisk_nfs_url}")

            # --- Optimization: Add '-S 4k' for sparse handling ---
            convert_cmd = f"/usr/local/nutanix/bin/qemu-img convert -p -S 4k -O qcow2 '{source_vdisk_nfs_url}' {remote_qcow2_path}"
            print(f"Converting disk on CVM (Sparse Mode enabled)...")
            _, convert_error, convert_status = self._run_remote_command(ssh_client, convert_cmd)

            if convert_status != 0:
                raise Exception(f"Remote qemu-img conversion failed: {convert_error}")

            print("Remote conversion successful.")

            print(f"Starting download from {remote_qcow2_path}...")
            local_qcow2_filename = f"{vm_name.replace(' ', '_')}_{disk_uuid}.qcow2"
            local_qcow2_path = os.path.join(output_dir, local_qcow2_filename)
            os.makedirs(output_dir, exist_ok=True)

            self._download_scp(ssh_client, remote_qcow2_path, local_qcow2_path)

            print("Download complete.")
            return local_qcow2_filename

        except Exception as e:
            error_message = str(e)
            if "NFS3ERR_JUKEBOX" in error_message:
                print("\nNOTE: 'NFS3ERR_JUKEBOX' detected. This usually indicates an empty or sparse disk I/O timeout.", file=sys.stderr)

            print(f"\nAn error occurred during the export process for disk {disk_uuid}: {e}", file=sys.stderr)
            return None
        finally:
            if ssh_client and ssh_client.get_transport() and ssh_client.get_transport().is_active():
                print(f"Cleaning up remote directory: {remote_temp_dir}")
                cleanup_cmd = f"rm -rf {remote_temp_dir}"
                self._run_remote_command(ssh_client, cleanup_cmd)

            if ssh_client:
                ssh_client.close()
                print("CVM connection closed.")

    def generate_and_save_qemu_script(self, vm_details, disk_files, output_dir):
        print("\nGenerating QEMU launch script...")
        vm_name = vm_details['name']
        
        command = f"#!/bin/sh\n\n"
        command += f"# Launch script for VM: {vm_name}\n\n"
        command += f"qemu-system-x86_64 \\\n"
        command += f"    -name \"{vm_name}\" \\\n"
        command += f"    -smp {vm_details['vcpus']} \\\n"
        command += f"    -m {vm_details['memory_mb']}M \\\n"
        command += f"    -enable-kvm \\\n"
        command += f"    -cpu host \\\n"
        
        for i, disk_file in enumerate(disk_files):
            base_disk_file = os.path.basename(disk_file)
            command += f"    -drive file=\"{base_disk_file}\",if=virtio,index={i},media=disk,format=qcow2,cache=writeback \\\n"
            
        command += f"    -vga std \\\n"
        command += f"    -net nic,model=virtio -net user,hostfwd=tcp::2222-:22\n"

        script_path = os.path.join(output_dir, f"start_{vm_name.replace(' ', '_')}.sh")
        try:
            with open(script_path, 'w') as f:
                f.write(command)
            os.chmod(script_path, 0o755)
            print(f"Successfully created QEMU launch script: {script_path}")
        except IOError as e:
            print(f"Error: Could not write script to {script_path}: {e}", file=sys.stderr)

    def generate_and_save_libvirt_xml(self, vm_details, disk_files, output_dir):
        print("\nGenerating libvirt XML definition...")
        vm_name = vm_details['name']
        
        domain = ET.Element('domain', type='kvm')
        ET.SubElement(domain, 'name').text = vm_name
        ET.SubElement(domain, 'uuid').text = vm_details['uuid']
        ET.SubElement(domain, 'memory', unit='MiB').text = str(vm_details['memory_mb'])
        ET.SubElement(domain, 'vcpu', placement='static').text = str(vm_details['vcpus'])
        
        os_elem = ET.SubElement(domain, 'os')
        ET.SubElement(os_elem, 'type', arch='x86_64', machine='pc-q35-latest').text = 'hvm'
        
        features = ET.SubElement(domain, 'features')
        ET.SubElement(features, 'acpi')
        ET.SubElement(features, 'apic')
        
        cpu = ET.SubElement(domain, 'cpu', mode='host-passthrough', check='none')
        
        devices = ET.SubElement(domain, 'devices')
        ET.SubElement(devices, 'emulator').text = '/usr/bin/qemu-system-x86_64'
        
        for i, disk_file in enumerate(disk_files):
            disk_path = os.path.abspath(os.path.join(output_dir, disk_file))
            disk = ET.SubElement(devices, 'disk', type='file', device='disk')
            ET.SubElement(disk, 'driver', name='qemu', type='qcow2')
            ET.SubElement(disk, 'source', file=disk_path)
            target_dev = 'vd' + chr(ord('a') + i)
            ET.SubElement(disk, 'target', dev=target_dev, bus='virtio')
            ET.SubElement(disk, 'boot', order=str(i+1))

        ET.SubElement(devices, 'controller', type='usb', index='0', model='qemu-xhci')
        ET.SubElement(devices, 'interface', type='network')
        ET.SubElement(ET.SubElement(devices, 'interface'), 'model', type='virtio')
        ET.SubElement(devices, 'graphics', type='spice', autoport='yes')

        xml_string = ET.tostring(domain, 'utf-8')
        reparsed = minidom.parseString(xml_string)
        pretty_xml = reparsed.toprettyxml(indent="  ")

        xml_path = os.path.join(output_dir, f"{vm_name.replace(' ', '_')}.xml")
        try:
            with open(xml_path, 'w') as f:
                f.write(pretty_xml)
            print(f"Successfully created libvirt XML definition: {xml_path}")
        except IOError as e:
            print(f"Error: Could not write XML to {xml_path}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Export a Nutanix AHV VM's disks to QCOW2 format.",
        epilog="Example: python3 nutanix-exporter.py 192.168.1.10 'My Web Server' --export-all"
    )
    parser.add_argument("cluster_ip", help="IP address of Prism Central or a CVM in the Nutanix cluster.")
    parser.add_argument("vm_name", nargs='?', default=None, help="The name of the VM to export. (Not needed for --inventory)")
    
    parser.add_argument("-u", "--username", help="Username for Prism.", default="admin")
    parser.add_argument("-p", "--password", help="Password for Prism. Falls back to NUTANIX_PASSWORD env var or prompt.")
    
    parser.add_argument("--cvm-user", help="Username for the CVM (for SSH/SFTP).", default="nutanix")
    parser.add_argument("--cvm-password", help="Password for the CVM. Falls back to CVM_PASSWORD env var or prompt.")
    
    parser.add_argument("-o", "--output-dir", help="Output directory for exported files.", default=".")
    parser.add_argument("--inventory", action="store_true", help="List all available VMs and exit.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for verbose output.")
    parser.add_argument("--force", action="store_true", help="Force export even if the VM is powered on (DANGEROUS).")
    parser.add_argument("--export-def", action="store_true", help="Export disks and a QEMU launch script.")
    parser.add_argument("--export-xml", action="store_true", help="Export disks and a libvirt XML file.")
    parser.add_argument("--export-all", action="store_true", help="Export disks, QEMU script, and libvirt XML.")

    args = parser.parse_args()

    if args.export_all:
        args.export_def = True
        args.export_xml = True

    # --- Security: Check Environment Variables first ---
    prism_password = args.password or os.environ.get('NUTANIX_PASSWORD')
    if not prism_password:
        prism_password = getpass.getpass(f"Enter password for Prism user '{args.username}': ")

    exporter = NutanixExporter(args.cluster_ip, args.username, prism_password, debug=args.debug)

    if args.inventory:
        exporter.list_all_vms()
        sys.exit(0)

    if not args.vm_name:
        parser.error("A vm_name is required for export operations.")
    
    export_disks_required = args.export_def or args.export_xml

    if not export_disks_required:
        # If user didn't specify what to export, default to just the disk? 
        # Or error? The original script exited. Let's act on export-all implicitly if flags missing?
        # For now, stick to original logic: exit if nothing requested.
        print("No export action specified (--export-def, --export-xml, --export-all). Nothing to do.")
        sys.exit(0)

    vm_details = exporter.get_vm_details(args.vm_name)
    if not vm_details:
        sys.exit(1)

    if vm_details['power_state'] != 'OFF':
        if not args.force:
            print(f"\nError: VM '{args.vm_name}' is currently powered ON ({vm_details['power_state']}).", file=sys.stderr)
            print("Please power off the VM before exporting to ensure data consistency.", file=sys.stderr)
            sys.exit(1)
        else:
            print("\nWARNING: Proceeding with export while VM is powered ON due to --force flag.")
            time.sleep(3) 
    else:
        print(f"VM '{args.vm_name}' is powered OFF. Proceeding with export.")

    if not vm_details['disks']:
        print(f"No exportable disks found for VM '{args.vm_name}'. Exiting.")
        sys.exit(1)

    cvm_password = args.cvm_password or os.environ.get('CVM_PASSWORD')
    if not cvm_password:
        cvm_password = getpass.getpass(f"Enter password for CVM user '{args.cvm_user}': ")

    exported_disk_files = []
    any_disk_failed = False
    for disk_info in vm_details['disks']:
        local_file = exporter.export_disk_to_qcow2(vm_details, disk_info, args.output_dir, args.cvm_user, cvm_password)
        if local_file:
            exported_disk_files.append(local_file)
        else:
            print(f"\nERROR: Failed to export disk {disk_info['uuid']}. Continuing to next disk...", file=sys.stderr)
            any_disk_failed = True

    if not exported_disk_files:
        print("\nFATAL: No disks were successfully exported.", file=sys.stderr)
        sys.exit(1)

    if args.export_def:
        exporter.generate_and_save_qemu_script(vm_details, exported_disk_files, args.output_dir)

    if args.export_xml:
        exporter.generate_and_save_libvirt_xml(vm_details, exported_disk_files, args.output_dir)

    if any_disk_failed:
        print("\nProcess complete, but one or more disks failed to export.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\nProcess complete.")

if __name__ == "__main__":
    main()
