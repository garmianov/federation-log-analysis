#!/usr/bin/env python3
"""
Federation Log Unzip Utility

Extracts log files from ZIP archives with proper server separation:
- Extracts server ID from zip filename (e.g., MS63870Fed.zip → MS63870)
- Creates a subfolder per server in the output directory
- Recursively unzips nested ZIP files
- Handles any number of servers dynamically

Usage:
    python unzip_logs.py <zip_file_or_directory> [output_dir]
    python unzip_logs.py ~/Downloads/MS63870Fed.zip
    python unzip_logs.py ~/Downloads/  # Process all MS*.zip files
    python unzip_logs.py ~/Downloads/ /path/to/output --replace
"""

import os
import re
import shutil
import sys
import zipfile
from pathlib import Path

# Default output directory
DEFAULT_OUTPUT_DIR = "/Volumes/MacMini/temps/claude/templogs"

# Pattern to extract server ID from filename (e.g., MS63870Fed.zip → MS63870)
SERVER_PATTERN = re.compile(r"(MS\d+)")


def extract_server_id(filename: str) -> str:
    """Extract server ID from zip filename."""
    match = SERVER_PATTERN.search(filename)
    if match:
        return match.group(1)
    # Fallback: use filename without extension
    return Path(filename).stem


def unzip_recursive(zip_path: str, output_dir: str, depth: int = 0) -> tuple[int, int]:
    """
    Recursively extract a ZIP file, including nested ZIPs.

    Returns: (files_extracted, nested_zips_processed)
    """
    files_extracted = 0
    nested_zips = 0
    indent = "  " * depth

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                # Skip directories and macOS metadata
                if member.endswith("/") or "/__MACOSX/" in member or member.startswith("__MACOSX"):
                    continue

                # Extract to output directory (flatten structure)
                filename = os.path.basename(member)
                if not filename:
                    continue

                output_path = os.path.join(output_dir, filename)

                # Handle duplicate filenames
                if os.path.exists(output_path):
                    base, ext = os.path.splitext(filename)
                    counter = 1
                    while os.path.exists(output_path):
                        output_path = os.path.join(output_dir, f"{base}_{counter}{ext}")
                        counter += 1

                # Extract file
                try:
                    with zf.open(member) as src, open(output_path, "wb") as dst:
                        dst.write(src.read())
                    files_extracted += 1

                    # If extracted file is a ZIP, recursively extract it
                    if output_path.endswith(".zip"):
                        print(f"{indent}  Nested ZIP: {filename}")
                        nested_files, nested_nested = unzip_recursive(
                            output_path, output_dir, depth + 1
                        )
                        files_extracted += nested_files
                        nested_zips += 1 + nested_nested
                        # Remove the nested zip after extraction
                        os.remove(output_path)
                        files_extracted -= 1  # Don't count the zip itself

                except Exception as e:
                    print(f"{indent}  Warning: Failed to extract {member}: {e}")

    except zipfile.BadZipFile:
        print(f"{indent}Warning: {zip_path} is not a valid ZIP file")
    except Exception as e:
        print(f"{indent}Error processing {zip_path}: {e}")

    return files_extracted, nested_zips


def process_zip_file(zip_path: str, base_output_dir: str) -> dict:
    """Process a single ZIP file with server separation."""
    filename = os.path.basename(zip_path)
    server_id = extract_server_id(filename)

    # Create server-specific output directory
    server_dir = os.path.join(base_output_dir, server_id)
    os.makedirs(server_dir, exist_ok=True)

    print(f"\nProcessing: {filename}")
    print(f"  Server ID: {server_id}")
    print(f"  Output: {server_dir}")

    files, nested = unzip_recursive(zip_path, server_dir)

    print(f"  Extracted: {files:,} files ({nested} nested ZIPs processed)")

    return {
        "zip_file": filename,
        "server_id": server_id,
        "files_extracted": files,
        "nested_zips": nested,
    }


def find_zip_files(path: str) -> list[str]:
    """Find all relevant ZIP files in a path."""
    path = os.path.expanduser(path)

    if os.path.isfile(path) and path.endswith(".zip"):
        return [path]

    if os.path.isdir(path):
        zip_files = []
        for f in os.listdir(path):
            if f.endswith(".zip") and ("MS" in f or "Fed" in f or "Base" in f):
                zip_files.append(os.path.join(path, f))
        # Sort by modification time (newest first)
        zip_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        return zip_files

    return []


def main():
    print("=" * 60)
    print("Federation Log Unzip Utility")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage: python unzip_logs.py <zip_file_or_directory> [output_dir] [--replace]")
        print("\nExamples:")
        print("  python unzip_logs.py ~/Downloads/MS63870Fed.zip")
        print("  python unzip_logs.py ~/Downloads/  # All MS*.zip files")
        print("  python unzip_logs.py ~/Downloads/ /custom/output/path")
        print("  python unzip_logs.py ~/Downloads/ --replace  # Clear existing first")
        sys.exit(1)

    input_path = os.path.expanduser(sys.argv[1])
    output_dir = DEFAULT_OUTPUT_DIR
    replace_existing = "--replace" in sys.argv

    # Check for custom output directory
    for arg in sys.argv[2:]:
        if not arg.startswith("--"):
            output_dir = os.path.expanduser(arg)
            break

    # Validate input
    if not os.path.exists(input_path):
        print(f"Error: Path not found: {input_path}")
        sys.exit(1)

    # Find ZIP files
    zip_files = find_zip_files(input_path)
    if not zip_files:
        print(f"No ZIP files found in: {input_path}")
        sys.exit(1)

    print(f"\nFound {len(zip_files)} ZIP file(s):")
    for zf in zip_files:
        size_mb = os.path.getsize(zf) / (1024 * 1024)
        print(f"  - {os.path.basename(zf)} ({size_mb:.1f} MB)")

    # Handle replace option
    if replace_existing and os.path.exists(output_dir):
        print(f"\n--replace specified: Clearing {output_dir}")
        shutil.rmtree(output_dir)

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Process each ZIP file
    results = []
    for zip_path in zip_files:
        result = process_zip_file(zip_path, output_dir)
        results.append(result)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    total_files = sum(r["files_extracted"] for r in results)
    total_nested = sum(r["nested_zips"] for r in results)
    servers = set(r["server_id"] for r in results)

    print(f"Servers processed: {len(servers)}")
    for server in sorted(servers):
        server_dir = os.path.join(output_dir, server)
        if os.path.exists(server_dir):
            file_count = len(
                [f for f in os.listdir(server_dir) if os.path.isfile(os.path.join(server_dir, f))]
            )
            print(f"  - {server}: {file_count:,} files")

    print(f"\nTotal files extracted: {total_files:,}")
    print(f"Nested ZIPs processed: {total_nested:,}")
    print(f"Output directory: {output_dir}")

    # List server directories
    print("\nServer directories created:")
    for server in sorted(servers):
        print(f"  {output_dir}/{server}/")


if __name__ == "__main__":
    main()
