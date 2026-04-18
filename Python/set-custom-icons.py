#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : set-custom-icons.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 19 Sep 2025

import argparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "http://127.0.0.1:8080/api/v2/custom-nodes"


def update_icon(base_url, bearer, kind_name, icon_name, icon_color, icon_type="font-awesome", verify=False):
    api_v2_custom_nodes_route = "/api/v2/custom-nodes"

    r = requests.get(
        url=f"{base_url}/{api_v2_custom_nodes_route}/{kind_name}",
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json"
        },
        verify=verify
    )

    if r.status_code == 404:
        print(f"[>] Custom icon for {kind_name} does not exist (HTTP {r.status_code}), creating it...")
        r = requests.post(
            url=f"{base_url}/{api_v2_custom_nodes_route}",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json"
            },
            json={
                "custom_types": {
                    kind_name: {
                        "icon": {
                            "type": icon_type,
                            "name": icon_name,
                            "color": icon_color
                        }
                    }
                }
            },
            verify=verify
        )
        if r.status_code == 200:
            print(f"  └──[+] Custom icon for {kind_name} updated successfully")
        else:
            print(f"  └──[!] Failed to update custom icon for {kind_name} (HTTP {r.status_code})")
            print(r.text)
            return

    elif r.status_code == 200:
        print(f"[>] Custom icon for {kind_name} already exists (HTTP {r.status_code}), updating it...")
        r = requests.put(
            url=f"{base_url}/{api_v2_custom_nodes_route}/{kind_name}",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json"
            },
            json={
                "config": {
                    "icon": {
                        "type": icon_type,
                        "name": icon_name,
                        "color": icon_color
                    }
                }
            },
            verify=verify
        )
        if r.status_code == 200:
            print(f"  └──[+] Custom icon for {kind_name} updated successfully")
        else:
            print(f"  └──[!] Failed to update custom icon for {kind_name} (HTTP {r.status_code})")
            print(r.text)
            return
    else:
        print(f"[!] Failed to get status of custom icon for {kind_name} (HTTP {r.status_code})")
        print(r.text)
        return


def parse_args():
    parser = argparse.ArgumentParser(description="Set custom icons for nodes")

    # BloodHound configuration
    bloodhound_group = parser.add_argument_group('BloodHound Configuration')
    bloodhound_group.add_argument("-H", "--host", type=str, default="127.0.0.1", help="BloodHound host")
    bloodhound_group.add_argument("-P", "--port", type=int, default=8080, help="BloodHound port")
    bloodhound_group.add_argument("-b", "--bearer", type=str, required=True, help="Bearer token for authentication")
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    url = f"http://{args.host}:{args.port}"

    update_icon(url, args.bearer, "NetworkShareSMB", "folder-tree", "#ffb1a3")
    update_icon(url, args.bearer, "NetworkShareDFS", "folder-tree", "#ffb1a3")
    update_icon(url, args.bearer, "File", "file", "#eaeaea")
    update_icon(url, args.bearer, "Directory", "folder", "#ffe08c")
    update_icon(url, args.bearer, "NetworkShareHost", "server", "#878a89")
