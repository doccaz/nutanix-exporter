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
        self.base_url_v3 = f"https://{self.cluster_ip}:9440/api/nutanix/v3"
        self.base_url_v2 = f"https://{self.cluster_ip}:9440/api/nutanix/v2.0"
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

    def _verify_image_exists_v3(self, image_uuid):
        """
        Queries the Prism v3 API to ensure the image UUID actually exists 
        in the library before we try to download it.
        """
        endpoint = f"{self.base_url_v3}/images/list"
        payload = {
            "kind": "image",
            "filter": f"uuid=={image_uuid}"
        }
        try:
            if self.debug: print(f"--- DEBUG: Verifying Image UUID {image_uuid} via API v3 ---")
            
            response = self.session.post(endpoint, data=json.dumps(payload))
            response.raise_for_status()
            data = response.json()
            
            total_matches = data.get('metadata', {}).get('total_matches', 0)
            if total_matches > 0:
                name = data['entities'][0]['spec'].get('name', 'Unknown')
                print(f"Verified Image in Library: '{name}'")
                return True
            else:
                print(f"Image UUID {image_uuid} not found in Prism Image Service (it may have been deleted).")
                return False
        except Exception as e:
            print(f"Warning: Could not verify image existence via API: {e}")
            return False

    def _download_image_from_api(self, image_uuid, local_path):
        """
        Downloads a disk image directly from the Prism Image Service API v3.
        """
        # Step 1: Verify existence to avoid 404/500 errors
        if not self._verify_image_exists_v3(image_uuid):
            return False

        # Step 2: Attempt Download
        url = f"{self.base_url_v3}/images/{image_uuid}/file"
        print(f"Attempting API v3 download from: {url}")
        
        try:
            with self.session.get(url, stream=True) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                
                filename = os.path.basename(local_path)
                with tqdm(total=total_size, unit='B', unit_scale=True, desc=f"Downloading {filename}") as pbar:
                    with open(local_path, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)
                            pbar.update(len(chunk))
            
            print("API Download successful!")
            return True
        except Exception as e:
            print(f"API Download failed: {e}")
            if os.path.exists(local_path):
                os.remove(local_path)
            return False

    def list_all_vms(self):
        print("Retrieving VM inventory...")
        endpoint = f"{self.base_url_v3}/vms/list"
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
        endpoint = f"{self.base_url_v3}/vms/list"
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
            
            detail_endpoint = f"{self.base_url_v3}/vms/{vm_uuid}"
            response = self.session.get(detail_endpoint)
            response.raise_for_status()
            vm_details = response.json()

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
                device_type = device_props.get('device_type', 'DISK')
                
                if disk.get('uuid'):
                    disk_size_mib = disk.get('disk_size_mib', 0)
                    adapter_type = device_props.get('disk_address', {}).get('adapter_type', 'SCSI')
                    
                    data_source = disk.get('data_source_reference', {})
                    image_uuid = None
                    if data_source.get('kind') == 'image':
                        image_uuid = data_source.get('uuid')

                    details['disks'].append({
                        'uuid': disk['uuid'],
                        'size_mib': disk_size_mib,
                        'adapter_type': adapter_type,
                        'device_type': device_type,
                        'is_empty': disk.get('is_empty', False),
                        'image_uuid': image_uuid 
                    })
            
            for nic in spec.get('nic_list', []):
                if nic.get('mac_address'):
                    details['nics'].append({
                        'mac_address': nic.get('mac_address'),
                        'uuid': nic.get('uuid')
                    })
            
            print(f"Found {len(details['disks'])} drive(s) (Disks/CDROMs) and {len(details['nics'])} NIC(s).")
            return details

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while communicating with the Nutanix API: {e}")
            return None

    def export_disk_to_qcow2(self, vm_details, disk_info, output_dir, export_cdroms=False):
        vm_name = vm_details['name']
        disk_uuid = disk_info['uuid']
        disk_size = disk_info.get('size_mib', 0)
        device_type = disk_info.get('device_type', 'DISK')
        image_uuid = disk_info.get('image_uuid')

        if device_type == 'CDROM' and not export_cdroms:
            print(f"Skipping export for CD-ROM {disk_uuid} (Use --export-cdroms to include).")
            return None

        print(f"\n===== Starting export for {device_type} {disk_uuid} =====")
        
        ext = "iso" if device_type == 'CDROM' else "qcow2"
        local_filename = f"{vm_name.replace(' ', '_')}_{disk_uuid}.{ext}"
        local_path = os.path.join(output_dir, local_filename)
        os.makedirs(output_dir, exist_ok=True)

        # --- STRATEGY 1: Direct API Download (Best for ISOs) ---
        if device_type == 'CDROM' and image_uuid:
            print(f"Detected Image Service backing for CDROM (UUID: {image_uuid}).")
            if self._download_image_from_api(image_uuid, local_path):
                return local_filename
            else:
                print("API download failed. Falling back to SSH/CVM method...")

        # --- STRATEGY 2: SSH / qemu-img / NFS (Fallback) ---
        remote_temp_dir = "export_temp"
        remote_filename = f"export_{disk_uuid}.{ext}"
        remote_path = f"{remote_temp_dir}/{remote_filename}"

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
                    print("WARNING: Low disk space on CVM. Proceeding...")
            except ValueError:
                pass 

            # 2. DISCOVERY
            print("Discovering path via CVM...")
            acli_cmd = f"/usr/local/nutanix/bin/acli -o json vm.get '{vm_name}' include_vmdisk_paths=1"
            acli_output, acli_error, acli_status = self._run_remote_command(acli_cmd)

            if acli_status != 0:
                raise Exception(f"'acli' failed: {acli_error or acli_output}")

            try:
                vm_data = json.loads(acli_output)
                if "data" in vm_data: vm_data = vm_data["data"]
                vm_config_root = next(iter(vm_data.values()))
                if "config" in vm_config_root: vm_config_root = vm_config_root["config"]
                disk_list = vm_config_root.get('disk_list', [])
                source_path_relative = None
                for disk in disk_list:
                    curr_uuid = disk.get('device_uuid')
                    if curr_uuid == disk_uuid:
                        source_path_relative = disk.get('vmdisk_nfs_path')
                        break
                
                if not source_path_relative:
                     if device_type == 'CDROM':
                         print("No backing file found for CDROM (Empty?). Skipping download.")
                         return None
                     raise Exception("Could not find disk path in ACLI output.")
                     
                source_nfs_url = f"nfs://{self.cluster_ip}{source_path_relative}"

            except json.JSONDecodeError:
                raise Exception("Failed to parse acli JSON output.")

            # 3. EXPORT
            if device_type == 'CDROM':
                # For CDROMs, assume 'raw' input to prevent probing (JUKEBOX error)
                convert_cmd = f"/usr/local/nutanix/bin/qemu-img convert -p -f raw -O raw '{source_nfs_url}' {remote_path}"
            else:
                convert_cmd = f"/usr/local/nutanix/bin/qemu-img convert -p -S 4k -O qcow2 '{source_nfs_url}' {remote_path}"

            print(f"Exporting image via qemu-img...")
            _, convert_err, convert_status = self._run_remote_command(convert_cmd)

            if convert_status != 0:
                # If it still fails with JUKEBOX, we can't do much more. Return None so it skips nicely.
                if "NFS3ERR_JUKEBOX" in convert_err:
                    print("Error: Image is locked by Nutanix Image Service (NFS3ERR_JUKEBOX). Skipping download.")
                    return None
                raise Exception(f"Export failed (qemu-img): {convert_err.strip()}")

            # 4. DOWNLOAD
            self._download_scp(remote_path, local_path)

            return local_filename

        except Exception as e:
            print(f"Export failed: {e}", file=sys.stderr)
            return None
        finally:
            try:
                self._run_remote_command(f"rm -rf {remote_temp_dir}", retry=True)
            except:
                pass

    def generate_and_save_qemu_script(self, vm_details, disk_files_map, output_dir):
        print("\nGenerating QEMU launch script...")
        vm_name = vm_details['name']
        topo = vm_details['cpu_topology']
        
        command = f"#!/bin/sh\n\n"
        command += f"# Launch script for VM: {vm_name}\n"
        command += f"qemu-system-x86_64 \\\n"
        command += f"    -name \"{vm_name}\" \\\n"
        command += f"    -machine q35,accel=kvm \\\n"
        command += f"    -smp sockets={topo['sockets']},cores={topo['cores']},threads={topo['threads']} \\\n"
        command += f"    -m {vm_details['memory_mb']}M \\\n"
        command += f"    -cpu host \\\n"
        
        has_scsi = any(d.get('adapter_type') == 'SCSI' for d in vm_details['disks'])
        if has_scsi:
            command += f"    -device virtio-scsi-pci,id=scsi0 \\\n"

        for i, disk_info in enumerate(vm_details['disks']):
            uuid = disk_info['uuid']
            filename = disk_files_map.get(uuid)
            adapter = disk_info.get('adapter_type', 'SCSI')
            device_type = disk_info.get('device_type', 'DISK')

            if device_type == 'CDROM':
                if filename:
                    command += f"    -drive file=\"{filename}\",media=cdrom,if=ide,index={i},readonly=on \\\n"
                else:
                    command += f"    -drive media=cdrom,if=ide,index={i},readonly=on \\\n"
                continue

            if filename:
                if adapter == 'SCSI':
                    command += f"    -drive file=\"{filename}\",if=none,id=disk{i},format=qcow2,cache=writeback \\\n"
                    command += f"    -device scsi-hd,drive=disk{i},bus=scsi0.0 \\\n"
                elif adapter == 'IDE':
                    command += f"    -drive file=\"{filename}\",if=ide,index={i},media=disk,format=qcow2,cache=writeback \\\n"
                elif adapter == 'SATA':
                    command += f"    -drive file=\"{filename}\",if=ide,index={i},media=disk,format=qcow2,cache=writeback \\\n"
                else:
                    command += f"    -drive file=\"{filename}\",if=virtio,index={i},media=disk,format=qcow2,cache=writeback \\\n"
        
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

    def generate_and_save_libvirt_xml(self, vm_details, disk_files_map, output_dir):
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

        for i, disk_info in enumerate(vm_details['disks']):
            uuid = disk_info['uuid']
            filename = disk_files_map.get(uuid)
            adapter = disk_info.get('adapter_type', 'SCSI')
            device_type = disk_info.get('device_type', 'DISK')

            if device_type == 'CDROM':
                disk = ET.SubElement(devices, 'disk', type='file', device='cdrom')
                ET.SubElement(disk, 'driver', name='qemu', type='raw')
                if filename:
                     disk_path = os.path.abspath(os.path.join(output_dir, filename))
                     ET.SubElement(disk, 'source', file=disk_path)
                ET.SubElement(disk, 'readonly')
            else:
                disk = ET.SubElement(devices, 'disk', type='file', device='disk')
                ET.SubElement(disk, 'driver', name='qemu', type='qcow2')
                if filename:
                    disk_path = os.path.abspath(os.path.join(output_dir, filename))
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
        epilog="Example: python3 nutanix-exporter.py 192.168.1.10 'My Web Server' --export-all --export-cdroms"
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
    parser.add_argument("--export-cdroms", action="store_true", help="Also download ISO images attached to CD-ROMs.")

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
        print(f"No exportable disks (or CDROMs) found for VM '{args.vm_name}'. Exiting.")
        sys.exit(1)

    if not exporter.cvm_pass:
        exporter.cvm_pass = getpass.getpass(f"Enter password for CVM user '{args.cvm_user}': ")

    exported_files_map = {} 
    any_disk_failed = False
    
    for disk_info in vm_details['disks']:
        local_file = exporter.export_disk_to_qcow2(vm_details, disk_info, args.output_dir, export_cdroms=args.export_cdroms)
        exported_files_map[disk_info['uuid']] = local_file
        
        if not local_file:
            if disk_info['device_type'] == 'DISK':
                print(f"\nERROR: Failed to export disk {disk_info['uuid']}.", file=sys.stderr)
                any_disk_failed = True
            elif disk_info['device_type'] == 'CDROM' and args.export_cdroms:
                 print(f"\nWarning: Failed to export CDROM {disk_info['uuid']}.", file=sys.stderr)

    disks_present = any(d['device_type'] == 'DISK' for d in vm_details['disks'])
    disks_exported = any(d['device_type'] == 'DISK' and exported_files_map.get(d['uuid']) for d in vm_details['disks'])

    if disks_present and not disks_exported:
        print("\nFATAL: No main disks were successfully exported.", file=sys.stderr)
        sys.exit(1)

    if args.export_def:
        exporter.generate_and_save_qemu_script(vm_details, exported_files_map, args.output_dir)

    if args.export_xml:
        exporter.generate_and_save_libvirt_xml(vm_details, exported_files_map, args.output_dir)

    if any_disk_failed:
        print("\nProcess complete, but one or more disks failed to export.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\nProcess complete.")

if __name__ == "__main__":
    main()

