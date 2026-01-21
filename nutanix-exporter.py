#!/usr/bin/env python3

import argparse
import json
import requests
import getpass
import os
import sys
import re
import shutil
import time
from urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as ET
from xml.dom import minidom

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

    def __init__(self, cluster_ip, username, password, cvm_user=None, cvm_pass=None, debug=False):
        self.cluster_ip = cluster_ip
        self.username = username
        self.password = password
        self.cvm_user = cvm_user
        self.cvm_pass = cvm_pass
        self.debug = debug
        self.base_url = f"https://{self.cluster_ip}:9440/api/nutanix/v3"
        self.session = self._create_session()
        self.ssh_client = None 
        self.progress_bars = {}

        if self.debug:
            print(f"Debug mode is ON")
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

    def _get_ssh_client(self):
        if self.ssh_client and self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active():
            return self.ssh_client

        if self.debug:
            print(f"--- DEBUG: (Re)Connecting SSH to {self.cluster_ip} ---")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.cluster_ip,
            port=22,
            username=self.cvm_user,
            password=self.cvm_pass,
            timeout=15,
            banner_timeout=30 
        )
        self.ssh_client = client
        return self.ssh_client

    def _run_remote_command(self, command, retry=True):
        try:
            ssh = self._get_ssh_client()
            if self.debug:
                print(f"--- DEBUG: Executing: {command} ---")

            stdin, stdout, stderr = ssh.exec_command(command, get_pty=False)
            
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            exit_status = stdout.channel.recv_exit_status()
            stdout.channel.close()
            time.sleep(0.5) 

            if self.debug:
                print(f"--- DEBUG: Exit: {exit_status} ---")

            return output, error, exit_status

        except (paramiko.SSHException, paramiko.ssh_exception.ChannelException, OSError) as e:
            if retry:
                print(f"SSH Connection lost ({e}). Reconnecting and retrying...")
                if self.ssh_client:
                    try: self.ssh_client.close()
                    except: pass
                self.ssh_client = None 
                time.sleep(1)
                return self._run_remote_command(command, retry=False)
            else:
                raise e

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

    def _download_scp(self, remote_path, local_path):
        try:
            ssh = self._get_ssh_client()
            with SCPClient(ssh.get_transport(), progress=self.progress) as scp:
                print(f"Downloading file {remote_path} to {local_path}...")
                scp.get(remote_path, local_path)
                
                for pbar in self.progress_bars.values():
                    pbar.close()

                print("File downloaded successfully!")

        except Exception as e:
            print(f"An error occurred during download: {e}")
            self.ssh_client = None

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

    def get_vm_details(self, vm_name, save_raw_json_to=None):
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

            # --- Save Raw JSON for reference ---
            if save_raw_json_to:
                os.makedirs(save_raw_json_to, exist_ok=True)
                json_filename = f"{vm_name.replace(' ', '_')}_nutanix.json"
                json_path = os.path.join(save_raw_json_to, json_filename)
                try:
                    with open(json_path, 'w') as f:
                        json.dump(vm_details, f, indent=2)
                    print(f"Saved raw Nutanix JSON configuration to: {json_path}")
                except IOError as e:
                    print(f"Warning: Failed to save raw JSON: {e}")

            spec = vm_details.get('spec', {}).get('resources', {})
            status = vm_details.get('status', {}).get('resources', {})

            # Capture detailed CPU topology
            num_sockets = spec.get('num_sockets', 1)
            num_vcpus_per_socket = spec.get('num_vcpus_per_socket', 1)
            num_threads_per_core = spec.get('num_threads_per_core', 1)

            details = {
                'name': vm_details.get('spec', {}).get('name', 'N/A'),
                'uuid': vm_details.get('metadata', {}).get('uuid'),
                'memory_mb': spec.get('memory_size_mib', 1024),
                'power_state': status.get('power_state', 'UNKNOWN'),
                'cpu_topology': {
                    'sockets': num_sockets,
                    'cores': num_vcpus_per_socket,
                    'threads': num_threads_per_core,
                    'total_vcpus': num_sockets * num_vcpus_per_socket * num_threads_per_core
                },
                'disks': [],
                'nics': []
            }

            for disk in spec.get('disk_list', []):
                device_props = disk.get('device_properties', {})
                if device_props.get('device_type') == 'DISK' and disk.get('uuid'):
                    disk_size_mib = disk.get('disk_size_mib', 0)
                    adapter_type = device_props.get('disk_address', {}).get('adapter_type', 'SCSI')
                    details['disks'].append({
                        'uuid': disk['uuid'],
                        'size_mib': disk_size_mib,
                        'adapter_type': adapter_type
                    })
            
            for nic in spec.get('nic_list', []):
                if nic.get('mac_address'):
                    details['nics'].append({
                        'mac_address': nic.get('mac_address'),
                        'uuid': nic.get('uuid')
                    })
            
            print(f"Found {len(details['disks'])} disk(s) and {len(details['nics'])} NIC(s).")
            return details

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while communicating with the Nutanix API: {e}")
            return None

    def export_disk_to_qcow2(self, vm_details, disk_info, output_dir):
        vm_name = vm_details['name']
        disk_uuid = disk_info['uuid']
        disk_size = disk_info.get('size_mib', 0)
        
        print(f"\n===== Starting export for disk {disk_uuid} =====")
        
        remote_temp_dir = "export_temp"
        remote_qcow2_filename = f"export_{disk_uuid}.qcow2"
        remote_qcow2_path = f"{remote_temp_dir}/{remote_qcow2_filename}"

        try:
            # 1. SETUP
            print(f"Preparing temporary workspace on CVM...")
            setup_cmd = f"mkdir -p {remote_temp_dir} && df -mP {remote_temp_dir} | awk 'NR==2 {{print $4}}'"
            output, error, status = self._run_remote_command(setup_cmd)
            
            if status != 0:
                raise Exception(f"Setup failed: {error}")
                
            try:
                available_mib = int(output.strip())
                print(f"CVM Space Available: {available_mib} MB")
                if available_mib < (disk_size + 1024): 
                    print("WARNING: Low disk space on CVM. Proceeding due to QCOW2 compression.")
            except ValueError:
                pass 

            # 2. DISCOVERY (ACLI)
            print("Discovering vdisk path via CVM...")
            acli_cmd = f"/usr/local/nutanix/bin/acli -o json vm.get '{vm_name}' include_vmdisk_paths=1"
            acli_output, acli_error, acli_status = self._run_remote_command(acli_cmd)

            if acli_status != 0:
                raise Exception(f"'acli' failed: {acli_error or acli_output}")

            # --- Save ACLI Layout ---
            acli_json_path = os.path.join(output_dir, f"{vm_name.replace(' ', '_')}_acli_layout.json")
            if not os.path.exists(acli_json_path):
                try:
                    parsed_acli = json.loads(acli_output)
                    with open(acli_json_path, 'w') as f:
                        json.dump(parsed_acli, f, indent=2)
                    print(f"Saved Nutanix ACLI disk layout to: {acli_json_path}")
                except Exception as e:
                    print(f"Warning: Failed to save ACLI layout: {e}")

            try:
                vm_data = json.loads(acli_output)
                if "data" in vm_data: vm_data = vm_data["data"]
                vm_config_root = None
                for val in vm_data.values():
                    if isinstance(val, dict) and "config" in val:
                        vm_config_root = val
                        break
                if not vm_config_root: vm_config_root = next(iter(vm_data.values()))
                disk_list = vm_config_root.get('config', {}).get('disk_list', [])
                source_vdisk_path_relative = None
                for disk in disk_list:
                    curr_uuid = disk.get('device_uuid')
                    if curr_uuid == disk_uuid:
                        source_vdisk_path_relative = disk.get('vmdisk_nfs_path')
                        break
                if not source_vdisk_path_relative:
                     print(f"DEBUG: Analyzed {len(disk_list)} disks from ACLI. Target: {disk_uuid}")
                     raise Exception("Could not find disk path in ACLI output.")
                source_vdisk_nfs_url = f"nfs://{self.cluster_ip}{source_vdisk_path_relative}"

            except json.JSONDecodeError:
                raise Exception("Failed to parse acli JSON output.")

            # 3. CONVERSION
            convert_cmd = f"/usr/local/nutanix/bin/qemu-img convert -p -S 4k -O qcow2 '{source_vdisk_nfs_url}' {remote_qcow2_path}"
            print(f"Converting disk (this may take time)...")
            _, convert_error, convert_status = self._run_remote_command(convert_cmd)

            if convert_status != 0:
                raise Exception(f"Conversion failed: {convert_error}")

            # 4. DOWNLOAD
            local_qcow2_filename = f"{vm_name.replace(' ', '_')}_{disk_uuid}.qcow2"
            local_qcow2_path = os.path.join(output_dir, local_qcow2_filename)
            
            os.makedirs(output_dir, exist_ok=True)
            self._download_scp(remote_qcow2_path, local_qcow2_path)

            return local_qcow2_filename

        except Exception as e:
            print(f"Export failed: {e}", file=sys.stderr)
            return None
        finally:
            # 5. CLEANUP with Retry=True
            try:
                self._run_remote_command(f"rm -rf {remote_temp_dir}", retry=True)
            except:
                pass

    def generate_and_save_qemu_script(self, vm_details, disk_files, output_dir):
        print("\nGenerating QEMU launch script...")
        vm_name = vm_details['name']
        topo = vm_details['cpu_topology']
        
        command = f"#!/bin/sh\n\n"
        command += f"# Launch script for VM: {vm_name}\n"
        command += f"# CPU: {topo['sockets']} Sockets, {topo['cores']} Cores, {topo['threads']} Threads\n\n"
        command += f"qemu-system-x86_64 \\\n"
        command += f"    -name \"{vm_name}\" \\\n"
        command += f"    -machine q35,accel=kvm \\\n"
        command += f"    -smp sockets={topo['sockets']},cores={topo['cores']},threads={topo['threads']} \\\n"
        command += f"    -m {vm_details['memory_mb']}M \\\n"
        command += f"    -cpu host \\\n"
        
        has_scsi = any(d.get('adapter_type') == 'SCSI' for d in vm_details['disks'])
        if has_scsi:
            command += f"    -device virtio-scsi-pci,id=scsi0 \\\n"

        for i, disk_file in enumerate(disk_files):
            base_disk_file = os.path.basename(disk_file)
            adapter = vm_details['disks'][i].get('adapter_type', 'SCSI')
            
            if adapter == 'SCSI':
                command += f"    -drive file=\"{base_disk_file}\",if=none,id=disk{i},format=qcow2,cache=writeback \\\n"
                command += f"    -device scsi-hd,drive=disk{i},bus=scsi0.0 \\\n"
            elif adapter == 'IDE':
                command += f"    -drive file=\"{base_disk_file}\",if=ide,index={i},media=disk,format=qcow2,cache=writeback \\\n"
            elif adapter == 'SATA':
                command += f"    -drive file=\"{base_disk_file}\",if=ide,index={i},media=disk,format=qcow2,cache=writeback \\\n"
            else:
                command += f"    -drive file=\"{base_disk_file}\",if=virtio,index={i},media=disk,format=qcow2,cache=writeback \\\n"
        
        if vm_details['nics']:
            for i, nic in enumerate(vm_details['nics']):
                mac = nic['mac_address']
                command += f"    -netdev user,id=net{i},hostfwd=tcp::222{i}-:22 \\\n"
                command += f"    -device virtio-net-pci,netdev=net{i},mac={mac} \\\n"
        else:
            command += f"    -net nic,model=virtio -net user,hostfwd=tcp::2222-:22 \\\n"
            
        command += f"    -vga std\n"

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
        topo = vm_details['cpu_topology']
        
        domain = ET.Element('domain', type='kvm')
        ET.SubElement(domain, 'name').text = vm_name
        ET.SubElement(domain, 'uuid').text = vm_details['uuid']
        ET.SubElement(domain, 'memory', unit='MiB').text = str(vm_details['memory_mb'])
        
        ET.SubElement(domain, 'vcpu', placement='static').text = str(topo['total_vcpus'])
        
        os_elem = ET.SubElement(domain, 'os')
        ET.SubElement(os_elem, 'type', arch='x86_64', machine='pc-q35-latest').text = 'hvm'
        
        features = ET.SubElement(domain, 'features')
        ET.SubElement(features, 'acpi')
        ET.SubElement(features, 'apic')
        
        cpu = ET.SubElement(domain, 'cpu', mode='host-passthrough', check='none')
        ET.SubElement(cpu, 'topology', sockets=str(topo['sockets']), cores=str(topo['cores']), threads=str(topo['threads']))
        
        devices = ET.SubElement(domain, 'devices')
        ET.SubElement(devices, 'emulator').text = '/usr/bin/qemu-system-x86_64'
        
        has_scsi = any(d.get('adapter_type') == 'SCSI' for d in vm_details['disks'])
        if has_scsi:
            ET.SubElement(devices, 'controller', type='scsi', index='0', model='virtio-scsi')

        for i, disk_file in enumerate(disk_files):
            disk_path = os.path.abspath(os.path.join(output_dir, disk_file))
            disk_info = vm_details['disks'][i]
            adapter = disk_info.get('adapter_type', 'SCSI')
            
            disk = ET.SubElement(devices, 'disk', type='file', device='disk')
            ET.SubElement(disk, 'driver', name='qemu', type='qcow2')
            ET.SubElement(disk, 'source', file=disk_path)
            
            if adapter == 'SCSI':
                target_bus = 'scsi'
                target_dev = 'sd' + chr(ord('a') + i)
            elif adapter == 'IDE':
                target_bus = 'ide'
                target_dev = 'hd' + chr(ord('a') + i)
            elif adapter == 'SATA':
                target_bus = 'sata'
                target_dev = 'sd' + chr(ord('a') + i)
            else:
                target_bus = 'virtio'
                target_dev = 'vd' + chr(ord('a') + i)

            ET.SubElement(disk, 'target', dev=target_dev, bus=target_bus)
            ET.SubElement(disk, 'boot', order=str(i+1))

        if vm_details['nics']:
            for nic in vm_details['nics']:
                interface = ET.SubElement(devices, 'interface', type='network')
                ET.SubElement(interface, 'mac', address=nic['mac_address'])
                ET.SubElement(interface, 'source', network='default')
                ET.SubElement(interface, 'model', type='virtio')
        else:
            ET.SubElement(ET.SubElement(devices, 'interface', type='network'), 'model', type='virtio')

        ET.SubElement(devices, 'controller', type='usb', index='0', model='qemu-xhci')
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

    prism_password = args.password or os.environ.get('NUTANIX_PASSWORD')
    if not prism_password:
        prism_password = getpass.getpass(f"Enter password for Prism user '{args.username}': ")

    cvm_password = args.cvm_password or os.environ.get('CVM_PASSWORD')

    exporter = NutanixExporter(
        args.cluster_ip, 
        args.username, 
        prism_password, 
        cvm_user=args.cvm_user,
        cvm_pass=cvm_password,
        debug=args.debug
    )

    if args.inventory:
        exporter.list_all_vms()
        sys.exit(0)

    if not args.vm_name:
        parser.error("A vm_name is required for export operations.")
    
    export_disks_required = args.export_def or args.export_xml

    if not export_disks_required:
        print("No export action specified (--export-def, --export-xml, --export-all). Nothing to do.")
        sys.exit(0)

    # Pass output_dir here to trigger JSON dump
    vm_details = exporter.get_vm_details(args.vm_name, save_raw_json_to=args.output_dir)
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

    if not exporter.cvm_pass:
        exporter.cvm_pass = getpass.getpass(f"Enter password for CVM user '{args.cvm_user}': ")

    exported_disk_files = []
    any_disk_failed = False
    for disk_info in vm_details['disks']:
        local_file = exporter.export_disk_to_qcow2(vm_details, disk_info, args.output_dir)
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

