#!/usr/bin/env python3
"""
Script to Auto Allocate NGFW Local Security Prefixes & Bindings
Author: Aaron Ratcliffe @ PANW
Version: 5..0 (Fix: More the one lcoal prefix per site localized)
"""
import argparse
import sys
import csv
import collections
import prisma_sase
import prismasase_settings

##############################################################################
# Init SDK
##############################################################################
sdk = prisma_sase.API(ssl_verify=False)
sdk.interactive.login_secret(client_id=prismasase_settings.client_id,
                             client_secret=prismasase_settings.client_secret,
                             tsg_id=prismasase_settings.scope)

##############################################################################
# Get Dics & Helpers
##############################################################################
def get_site_map():
    print("Loading Site map...")
    site_map = {}
    resp = sdk.get.sites()
    if not resp.ok:
        print(f"ERROR: Could not retrieve sites. {resp.status_code}")
        sys.exit(1)
    for item in resp.json().get('items', []):
        site_map[item['name']] = item['id']
    return site_map

def get_ngfw_prefix_containers():
    print("Loading NGFW Security Local Prefix Containers...")
    prefix_map = {}
    
    # Try native SDK get method
    if hasattr(sdk.get, "ngfwsecuritypolicylocalprefixes"):
        resp = sdk.get.ngfwsecuritypolicylocalprefixes()
    else:
        # Fallback to older SDK naming or REST
        if hasattr(sdk.get, "ngfw_security_policy_local_prefixes"):
            resp = sdk.get.ngfw_security_policy_local_prefixes()
        else:
            resp = sdk.rest_call("/ngfwsecuritypolicylocalprefixes", "GET")

    if not resp.ok:
        print(f"ERROR: Could not retrieve prefix containers ({resp.status_code}).")
        sys.exit(1)
        
    for item in resp.json().get('items', []):
        prefix_map[item['name']] = item['id']
    return prefix_map

##############################################################################
# Core Logic
##############################################################################
def process_bindings(csv_file_path):
    print(f"\nProcessing Bindings from CSV: {csv_file_path}\n" + "="*50)
    
    # Load Maps
    site_id_map = get_site_map()
    container_map = get_ngfw_prefix_containers()

    pending_data = collections.defaultdict(lambda: collections.defaultdict(set))
    target_prefixes = []

    # READ & AGGREGATE CSV
    print("Reading and aggregating CSV data...")
    try:
        with open(csv_file_path, mode='r', encoding='utf-8-sig') as infile:
            reader = csv.DictReader(infile)
            all_headers = reader.fieldnames
            if not all_headers:
                print("ERROR: CSV empty.")
                return
            
            # Filter out non-prefix columns
            ignore_cols = ['site_name', 'SDK', 'serial_number', 'hostname'] 
            target_prefixes = [h for h in all_headers if h and h not in ignore_cols]
            print(f"Detected Prefixes: {target_prefixes}")

            for row in reader:
                site_name = row.get('site_name')
                if not site_name: continue
                
                for header in target_prefixes:
                    cidr = row.get(header)
                    if cidr and cidr.strip():
                        pending_data[site_name][header].add(cidr.strip())

    except FileNotFoundError:
        print(f"ERROR: File '{csv_file_path}' not found.")
        return

    # VERIFY CONTAINERS
    print("\n--- Verifying Prefix Containers ---")
    for p_name in target_prefixes:
        if p_name not in container_map:
            print(f"  > Creating new Container: '{p_name}'...")
            payload = {"name": p_name, "description": "Created via SDK"}
            # Helper to create container
            if hasattr(sdk.post, "ngfwsecuritypolicylocalprefixes"):
                resp = sdk.post.ngfwsecuritypolicylocalprefixes(data=payload)
            else:
                resp = sdk.rest_call("/ngfwsecuritypolicylocalprefixes", "POST", data=payload)
                
            if resp.ok:
                new_id = resp.json()['id']
                container_map[p_name] = new_id
                print(f"    SUCCESS. ID: {new_id}")
            else:
                print(f"    FAILED to create container: {resp.text}")

    # PROCESS SITES (Sync Data)
    print("\n--- Syncing Site Bindings ---")
    for site_name, prefixes_data in pending_data.items():
        site_id = site_id_map.get(site_name)
        if not site_id:
            continue

        print(f"Processing Site: {site_name}")

        current_bindings_map = {} 
        try:
            # SDK Call to get existing bindings
            resp = sdk.get.site_ngfwsecuritypolicylocalprefixes(site_id=site_id)
            if resp.ok:
                for b in resp.json().get('items', []):
                    current_bindings_map[b['prefix_id']] = b
        except Exception as e:
            print(f"  > Warning: Could not fetch existing bindings: {e}")

        for header, new_cidrs_set in prefixes_data.items():
            container_id = container_map.get(header)
            if not container_id:
                print(f"  > ERROR: ID for '{header}' not found.")
                continue

            existing_binding = current_bindings_map.get(container_id)
            
            if existing_binding:
                # === UPDATE (PUT) ===
                binding_id = existing_binding['id']
                current_ips = set(existing_binding.get('ipv4_prefixes', []))
                merged_ips = list(current_ips.union(new_cidrs_set))
                
                # Check for changes
                if len(merged_ips) > len(current_ips):
                    print(f"  > Appending {len(new_cidrs_set)} IPs to '{header}'...")

                    # Sanitize Tags (Null -> [])
                    existing_tags = existing_binding.get('tags')
                    if existing_tags is None:
                        existing_tags = []
                    
                    # --- THE FIX: Match User's Working Payload Exact Structure ---
                    # No "id", No "_etag". Just the data.
                    payload = {
                        "prefix_id": container_id,
                        "ipv4_prefixes": merged_ips,
                        "ipv6_prefixes": [],
                        "tags": existing_tags
                    }
                    
                    try:
                        # SDK PUT: (site_id, binding_id, data)
                        resp = sdk.put.site_ngfwsecuritypolicylocalprefixes(site_id, binding_id, data=payload)
                        
                        if resp.ok:
                            print(f"    SUCCESS: Updated.")
                        else:
                            print(f"    FAILED Update: {resp.status_code} - {resp.text}")
                    except Exception as e:
                        print(f"    ERROR calling PUT: {e}")
                else:
                    print(f"  > '{header}' is up to date.")

            else:
                # === CREATE (POST) ===
                print(f"  > Creating new binding for '{header}'...")
                # POST Payload
                payload = {
                    "prefix_id": container_id,
                    "ipv4_prefixes": list(new_cidrs_set),
                    "ipv6_prefixes": [],
                    "tags": []
                }
                try:
                    resp = sdk.post.site_ngfwsecuritypolicylocalprefixes(site_id=site_id, data=payload)
                    if resp.ok:
                        print(f"    SUCCESS: Created.")
                    else:
                        print(f"    FAILED Create: {resp.status_code} - {resp.text}")
                except Exception as e:
                    print(f"    ERROR calling POST: {e}")

##############################################################################
# Main
##############################################################################
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=False, help="Path to CSV")
    args = parser.parse_args()
    
    csv_file = args.file if args.file else "sec_prefix.csv"
    process_bindings(csv_file)

if __name__ == "__main__":
    main()
