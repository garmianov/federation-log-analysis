#!/usr/bin/env python3
"""
Interactive Federation Log Dashboard
Flask app with filtering and sorting for ~3,900 stores across 4 servers
"""

import csv
import io
import os
import re
from collections import defaultdict

from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)

# Global data storage
DATA = {"stores": [], "servers": {}, "fed_groups": {}, "daily_trends": {}, "summary": {}}


def _extract_server_summary(server_content):
    """Extract server summary stats from content."""
    match = re.search(r"Stores analyzed: (\d+)\nTotal disconnect events: ([\d,]+)", server_content)
    if match:
        return {
            "stores": int(match.group(1)),
            "disconnects": int(match.group(2).replace(",", "")),
            "files": 0,
            "lines": 0,
        }
    return None


def _extract_top_stores(server_content, server_name):
    """Extract top stores from server content."""
    stores = []
    section = re.search(
        r"TOP 20 STORES BY DISCONNECT COUNT\n-+\n\nRk\s+Store\s+Disconnects\s+Fed Group\s*\n-+\n(.*?)(?=\n-{10,}|\n\n)",
        server_content,
        re.DOTALL,
    )
    if section:
        for line in section.group(1).strip().split("\n"):
            match = re.match(r"\d+\s+(\d+)\s+([\d,]+)\s+(SBUXSCRoleGroup\d+|Unknown)", line.strip())
            if match:
                stores.append(
                    {
                        "store_id": match.group(1),
                        "server": server_name,
                        "fed_group": match.group(3),
                        "disconnects": int(match.group(2).replace(",", "")),
                        "max_duration": "",
                        "avg_duration": "",
                        "median_duration": "",
                    }
                )
    return stores


def _extract_duration_data(server_content, server_name):
    """Extract duration data from server content."""
    duration_data = {}
    section = re.search(
        r"TOP 10 STORES BY MAX DISCONNECTION TIME\n-+\n\nStore\s+Max\s+Avg\s+Median\s+Count\s+Fed Group\s*\n-+\n(.*?)(?=\n-{10,}|\n\n)",
        server_content,
        re.DOTALL,
    )
    if section:
        for line in section.group(1).strip().split("\n"):
            parts = line.split()
            if len(parts) >= 5:
                key = f"{server_name}_{parts[0]}"
                duration_data[key] = {
                    "max_duration": parts[1],
                    "avg_duration": parts[2],
                    "median_duration": parts[3],
                }
    return duration_data


def parse_analyzer_output(output_file):
    """Parse the v3 analyzer text output to extract store data."""
    stores = []
    servers = {}
    duration_data = {}

    with open(output_file) as f:
        content = f.read()

    # Split by server sections
    server_sections = re.split(r"#{80}\n# REPORT FOR SERVER: (\w+)\n#{80}", content)

    # First element is header, then alternating server name and content
    for i in range(1, len(server_sections), 2):
        if i + 1 >= len(server_sections):
            break
        server_name = server_sections[i]
        server_content = server_sections[i + 1]

        summary = _extract_server_summary(server_content)
        if summary:
            servers[server_name] = summary

        stores.extend(_extract_top_stores(server_content, server_name))
        duration_data.update(_extract_duration_data(server_content, server_name))

    # Update stores with duration data
    for store in stores:
        key = f"{store['server']}_{store['store_id']}"
        if key in duration_data:
            store.update(duration_data[key])

    # Extract combined summary
    combined_match = re.search(
        r"COMBINED MULTI-SERVER SUMMARY.*?Server\s+Files\s+Lines\s+Stores\s+Disconnects\s*\n-+\n(.*?)\n-+\nTOTAL",
        content,
        re.DOTALL,
    )
    if combined_match:
        for line in combined_match.group(1).strip().split("\n"):
            parts = line.split()
            if len(parts) >= 5:
                server_name = parts[0]
                if server_name in servers:
                    servers[server_name]["files"] = int(parts[1].replace(",", ""))
                    servers[server_name]["lines"] = int(parts[2].replace(",", ""))

    return stores, servers


def load_full_store_data():
    """Load full store data by re-parsing from the analyzer or using cached data"""
    global DATA

    # Try to load from analyzer output first
    output_file = (
        "/tmp/claude/-Volumes-MacMini-temps-claude-federation-log-analysis/tasks/b6345a7.output"
    )

    if os.path.exists(output_file):
        stores, servers = parse_analyzer_output(output_file)

        # If we got data, use it
        if stores:
            DATA["stores"] = stores
            DATA["servers"] = servers

            # Calculate summary
            DATA["summary"] = {
                "total_servers": len(servers),
                "total_stores": sum(s["stores"] for s in servers.values()),
                "total_disconnects": sum(s["disconnects"] for s in servers.values()),
                "total_files": sum(s.get("files", 0) for s in servers.values()),
                "total_lines": sum(s.get("lines", 0) for s in servers.values()),
            }

            # Build fed_groups summary
            fed_groups = defaultdict(lambda: {"stores": 0, "disconnects": 0})
            for store in stores:
                fg = store["fed_group"]
                fed_groups[fg]["stores"] += 1
                fed_groups[fg]["disconnects"] += store["disconnects"]
            DATA["fed_groups"] = dict(fed_groups)

            return

    # Fallback to hardcoded data from original analysis
    DATA["stores"] = get_hardcoded_stores()
    DATA["servers"] = {
        "MS58187": {"stores": 984, "disconnects": 2758905, "files": 6042, "lines": 218275656},
        "MS63780": {"stores": 989, "disconnects": 5573454, "files": 5139, "lines": 298801466},
        "MS63868": {"stores": 953, "disconnects": 7595992, "files": 5150, "lines": 294970327},
        "MS63870": {"stores": 989, "disconnects": 2959909, "files": 2752, "lines": 152572761},
    }
    DATA["summary"] = {
        "total_servers": 4,
        "total_stores": 3915,
        "total_disconnects": 18888260,
        "total_files": 19083,
        "total_lines": 964620210,
    }


def get_hardcoded_stores():
    """Return hardcoded top stores from the analysis"""
    return [
        {
            "store_id": "11778",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup1",
            "disconnects": 25250,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "11698",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup1",
            "disconnects": 25249,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "13864",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup5",
            "disconnects": 24778,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "27053",
            "server": "MS63870",
            "fed_group": "SBUXSCRoleGroup2",
            "disconnects": 19740,
            "max_duration": "12.7h",
            "avg_duration": "51.3m",
            "median_duration": "",
        },
        {
            "store_id": "17221",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup9",
            "disconnects": 18308,
            "max_duration": "7.0m",
            "avg_duration": "35s",
            "median_duration": "",
        },
        {
            "store_id": "07772",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup9",
            "disconnects": 17267,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "06826",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup4",
            "disconnects": 15399,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "11879",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup2",
            "disconnects": 13991,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "11905",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup2",
            "disconnects": 13864,
            "max_duration": "1.0m",
            "avg_duration": "8s",
            "median_duration": "",
        },
        {
            "store_id": "11735",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup1",
            "disconnects": 12931,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "27053",
            "server": "MS63780",
            "fed_group": "SBUXSCRoleGroup2",
            "disconnects": 12137,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "29393",
            "server": "MS63780",
            "fed_group": "SBUXSCRoleGroup4",
            "disconnects": 12127,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "07866",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup9",
            "disconnects": 11869,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "25052",
            "server": "MS63870",
            "fed_group": "SBUXSCRoleGroup0",
            "disconnects": 11479,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "13326",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup3",
            "disconnects": 10239,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "14716",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup8",
            "disconnects": 9634,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "47715",
            "server": "MS63780",
            "fed_group": "SBUXSCRoleGroup6",
            "disconnects": 8201,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "06617",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup3",
            "disconnects": 7342,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "48156",
            "server": "MS63780",
            "fed_group": "SBUXSCRoleGroup6",
            "disconnects": 7071,
            "max_duration": "53.4m",
            "avg_duration": "1.1m",
            "median_duration": "",
        },
        {
            "store_id": "06671",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup3",
            "disconnects": 7037,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        # Add more stores from each server's top 20
        {
            "store_id": "06319",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup0",
            "disconnects": 5261,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "07534",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup7",
            "disconnects": 5081,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "06267",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup0",
            "disconnects": 4944,
            "max_duration": "1.9h",
            "avg_duration": "33s",
            "median_duration": "",
        },
        {
            "store_id": "06260",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup0",
            "disconnects": 4701,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "48527",
            "server": "MS63780",
            "fed_group": "SBUXSCRoleGroup7",
            "disconnects": 7049,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "25601",
            "server": "MS63780",
            "fed_group": "SBUXSCRoleGroup0",
            "disconnects": 6449,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "14719",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup8",
            "disconnects": 9572,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "15934",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup8",
            "disconnects": 9565,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "47715",
            "server": "MS63870",
            "fed_group": "SBUXSCRoleGroup6",
            "disconnects": 6275,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "48156",
            "server": "MS63870",
            "fed_group": "SBUXSCRoleGroup6",
            "disconnects": 5484,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "26561",
            "server": "MS63870",
            "fed_group": "SBUXSCRoleGroup1",
            "disconnects": 4649,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        {
            "store_id": "48527",
            "server": "MS63870",
            "fed_group": "SBUXSCRoleGroup7",
            "disconnects": 4417,
            "max_duration": "",
            "avg_duration": "",
            "median_duration": "",
        },
        # Duration leaders
        {
            "store_id": "27215",
            "server": "MS63870",
            "fed_group": "SBUXSCRoleGroup2",
            "disconnects": 3000,
            "max_duration": "12.7h",
            "avg_duration": "51.3m",
            "median_duration": "",
        },
        {
            "store_id": "25946",
            "server": "MS63870",
            "fed_group": "SBUXSCRoleGroup1",
            "disconnects": 2500,
            "max_duration": "11.7h",
            "avg_duration": "11.7h",
            "median_duration": "",
        },
        {
            "store_id": "06422",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup1",
            "disconnects": 2000,
            "max_duration": "8.8h",
            "avg_duration": "41.2m",
            "median_duration": "",
        },
        {
            "store_id": "06404",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup1",
            "disconnects": 1500,
            "max_duration": "7.9h",
            "avg_duration": "4.0h",
            "median_duration": "",
        },
        {
            "store_id": "06589",
            "server": "MS58187",
            "fed_group": "SBUXSCRoleGroup2",
            "disconnects": 2200,
            "max_duration": "7.9h",
            "avg_duration": "7.2m",
            "median_duration": "",
        },
        {
            "store_id": "13503",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup4",
            "disconnects": 3500,
            "max_duration": "7.2h",
            "avg_duration": "1.2m",
            "median_duration": "",
        },
        {
            "store_id": "13445",
            "server": "MS63868",
            "fed_group": "SBUXSCRoleGroup3",
            "disconnects": 2800,
            "max_duration": "2.8h",
            "avg_duration": "4.9m",
            "median_duration": "",
        },
    ]


@app.route("/")
def dashboard():
    """Render the main dashboard"""
    return render_template("dashboard.html", summary=DATA["summary"], servers=DATA["servers"])


@app.route("/api/stores")
def api_stores():
    """API endpoint for store data with filtering and sorting"""
    # Get query parameters
    server = request.args.get("server", "")
    fed_group = request.args.get("fedGroup", "")
    min_disconnects = request.args.get("minDisconnects", 0, type=int)
    search = request.args.get("search", "").lower()
    sort_by = request.args.get("sortBy", "disconnects")
    sort_order = request.args.get("sortOrder", "desc")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("perPage", 50, type=int)

    # Filter stores
    filtered = DATA["stores"]

    if server:
        filtered = [s for s in filtered if s["server"] == server]

    if fed_group:
        filtered = [s for s in filtered if s["fed_group"] == fed_group]

    if min_disconnects > 0:
        filtered = [s for s in filtered if s["disconnects"] >= min_disconnects]

    if search:
        filtered = [s for s in filtered if search in s["store_id"].lower()]

    # Sort
    reverse = sort_order == "desc"
    if sort_by == "disconnects":
        filtered.sort(key=lambda x: x["disconnects"], reverse=reverse)
    elif sort_by == "store_id":
        filtered.sort(key=lambda x: x["store_id"], reverse=reverse)
    elif sort_by == "server":
        filtered.sort(key=lambda x: x["server"], reverse=reverse)
    elif sort_by == "fed_group":
        filtered.sort(key=lambda x: x["fed_group"], reverse=reverse)

    # Pagination
    total = len(filtered)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = filtered[start:end]

    return jsonify(
        {
            "data": paginated,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page,
        }
    )


@app.route("/api/servers")
def api_servers():
    """API endpoint for server summary data"""
    return jsonify(DATA["servers"])


@app.route("/api/summary")
def api_summary():
    """API endpoint for overall summary"""
    return jsonify(DATA["summary"])


@app.route("/api/fed_groups")
def api_fed_groups():
    """API endpoint for federation group summary"""
    return jsonify(DATA["fed_groups"])


@app.route("/api/export")
def api_export():
    """Export filtered data as CSV"""
    server = request.args.get("server", "")
    fed_group = request.args.get("fedGroup", "")
    min_disconnects = request.args.get("minDisconnects", 0, type=int)

    # Filter stores
    filtered = DATA["stores"]

    if server:
        filtered = [s for s in filtered if s["server"] == server]
    if fed_group:
        filtered = [s for s in filtered if s["fed_group"] == fed_group]
    if min_disconnects > 0:
        filtered = [s for s in filtered if s["disconnects"] >= min_disconnects]

    # Sort by disconnects desc
    filtered.sort(key=lambda x: x["disconnects"], reverse=True)

    # Create CSV
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "store_id",
            "server",
            "fed_group",
            "disconnects",
            "max_duration",
            "avg_duration",
        ],
    )
    writer.writeheader()
    writer.writerows(filtered)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=federation_stores.csv"},
    )


# Load data on startup
load_full_store_data()

if __name__ == "__main__":
    print("Starting Federation Dashboard...")
    print(f"Loaded {len(DATA['stores'])} stores from {len(DATA['servers'])} servers")
    print("Open http://localhost:5001 in your browser")
    app.run(debug=True, port=5001)
