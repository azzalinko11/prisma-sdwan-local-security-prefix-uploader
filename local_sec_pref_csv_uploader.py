#!/usr/bin/env python3
"""
Script to Auto Allocate NGFW Local Security Prefixes & Bindings
Author: Aaron Ratcliffe @ PANW
Version: 4.0.0
"""
import argparse
import sys
import csv
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
# Build Dicts
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
    """
    Fetches the 'Container' objects.
    """
    print("Loading NGFW Security Local Prefix Containers...")
    prefix_map = {}
    
    # Check for get method or fallback
    if hasattr(sdk.get, "ngfwsecuritypolicylocalprefixes"):
        resp = sdk.get.ngfwsecuritypolicylocalprefixes()
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
    
    # 1. Load Maps
    site_id_map = get_site_map()
    container_map = get_ngfw_prefix_containers()

    try:
        with open(csv_file_path, mode='r', encoding='utf-8-sig') as infile:
            reader = csv.DictReader(infile)
            
            # --- DYNAMIC HEADER LOGIC ---
            # Get all column names from the CSV
            all_headers = reader.fieldnames
            if not all_headers:
                print("ERROR: CSV appears to be empty or missing headers.")
                return

            # Filter out 'site_name' to get just the prefix list
            target_prefixes = [h for h in all_headers if h and h != 'site_name']
            
            print(f"Detected Prefix Columns: {target_prefixes}")
            print("-" * 50)

            # Ensure Containers Exist (Global Objects)
            print("\n--- Verifying Prefix Containers ---")
            for p_name in target_prefixes:
                if p_name not in container_map:
                    print(f"  > Creating new Container: '{p_name}'...")
                    payload = {"name": p_name, "description": "Created via script"}
                    
                    resp = sdk.post.ngfwsecuritypolicylocalprefixes(data=payload)
                    
                    if resp.ok:
                        new_id = resp.json()['id']
                        container_map[p_name] = new_id
                        print(f"    SUCCESS. ID: {new_id}")
                    else:
                        print(f"    FAILED to create container: {resp.text}")
                else:
                    print(f"  > Found existing container: '{p_name}'")

            # 3. Process CSV Rows (Site Bindings)
            print("\n--- Processing Site Bindings ---")
            for row in reader:
                site_name = row.get('site_name')
                if not site_name: continue

                site_id = site_id_map.get(site_name)
                if not site_id:
                    print(f"SKIPPING '{site_name}': Site not found.")
                    continue

                print(f"Processing Site: {site_name}")

                for header in target_prefixes:
                    cidr = row.get(header)
                    # Skip empty cells
                    if not cidr or cidr.strip() == "": 
                        continue 
                    
                    container_id = container_map.get(header)
                    
                    # PAYLOAD
                    payload = {
                        "prefix_id": container_id,
                        "ipv4_prefixes": [cidr],
                        "ipv6_prefixes": [],
                        "tags": []
                    }
                    
                    try:
                        # Using the method we verified earlier
                        resp = sdk.post.site_ngfwsecuritypolicylocalprefixes(site_id=site_id, data=payload)

                        if resp.ok:
                            print(f"  > SUCCESS: Bound {cidr} to '{header}'")
                        else:
                            if resp.status_code == 409 or "already exists" in resp.text:
                                print(f"  > INFO: Binding exists.")
                            else:
                                print(f"  > FAILED: {resp.status_code} - {resp.text}")
                                
                    except Exception as e:
                        print(f"  > ERROR Calling SDK: {e}")

    except FileNotFoundError:
        print(f"ERROR: File '{csv_file_path}' not found.")
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")

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
