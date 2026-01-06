#!/usr/bin/env python3
"""
Windows 10/11 Prefetch Parser for Linux
Handles MAM (LZXPRESS Huffman) compressed prefetch files without Windows APIs

Requirements: pip install dissect.util

Author: Cross-platform forensics solution
"""

import argparse
import struct
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

try:
    from dissect.util.compression import lzxpress_huffman
except ImportError:
    print("Error: dissect.util required. Install with: pip install dissect.util")
    exit(1)


def filetime_to_datetime(filetime):
    """Convert Windows FILETIME to datetime (UTC)"""
    if filetime == 0:
        return None
    EPOCH_DIFF = 116444736000000000
    timestamp = (filetime - EPOCH_DIFF) / 10_000_000
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OSError, ValueError):
        return None


def parse_prefetch(filepath):
    """Parse a Windows Prefetch file and return structured data"""
    with open(filepath, "rb") as f:
        data = f.read()

    result = {
        "source_file": str(filepath),
        "compressed": False,
        "version": None,
        "version_string": None,
        "executable": None,
        "hash": None,
        "run_count": None,
        "last_run_times": [],
        "volumes": [],
        "files": [],
        "directories": []
    }

    # Check for MAM compression (Windows 10+)
    if data[:4] == b'MAM\x04':
        result["compressed"] = True
        decompressed_size = struct.unpack_from('<I', data, 4)[0]
        compressed_data = data[8:]
        data = lzxpress_huffman.decompress(compressed_data)

    # Validate signature
    signature = data[4:8]
    if signature != b'SCCA':
        raise ValueError(f"Invalid prefetch signature: {signature}")

    # Parse header
    version = struct.unpack_from('<I', data, 0)[0]
    result["version"] = version
    
    version_map = {
        17: "Windows XP/2003",
        23: "Windows Vista/7",
        26: "Windows 8/8.1",
        30: "Windows 10",
        31: "Windows 11"
    }
    result["version_string"] = version_map.get(version, f"Unknown ({version})")

    # Executable name
    result["executable"] = data[16:76].decode('utf-16-le').rstrip('\x00')
    result["hash"] = f"{struct.unpack_from('<I', data, 76)[0]:08X}"

    # Version-specific parsing
    if version in (30, 31):  # Windows 10/11
        metrics_offset = struct.unpack_from('<I', data, 84)[0]
        metrics_count = struct.unpack_from('<I', data, 88)[0]
        
        trace_offset = struct.unpack_from('<I', data, 92)[0]
        trace_count = struct.unpack_from('<I', data, 96)[0]
        
        filename_offset = struct.unpack_from('<I', data, 100)[0]
        filename_size = struct.unpack_from('<I', data, 104)[0]
        
        volumes_offset = struct.unpack_from('<I', data, 108)[0]
        volumes_count = struct.unpack_from('<I', data, 112)[0]
        volumes_size = struct.unpack_from('<I', data, 116)[0]
        
        result["run_count"] = struct.unpack_from('<I', data, 124)[0]

        # Last run times (up to 8)
        for i in range(8):
            ft = struct.unpack_from('<Q', data, 128 + (i * 8))[0]
            if ft:
                dt = filetime_to_datetime(ft)
                if dt:
                    result["last_run_times"].append(dt.strftime('%Y-%m-%d %H:%M:%S UTC'))

        # Parse volumes
        vol_data = data[volumes_offset:volumes_offset + volumes_size]
        for v in range(volumes_count):
            vol_entry_offset = v * 104
            if vol_entry_offset + 104 > len(vol_data):
                break
            
            vol_name_offset = struct.unpack_from('<I', vol_data, vol_entry_offset)[0]
            vol_name_len = struct.unpack_from('<I', vol_data, vol_entry_offset + 4)[0]
            vol_create_time = struct.unpack_from('<Q', vol_data, vol_entry_offset + 8)[0]
            vol_serial = struct.unpack_from('<I', vol_data, vol_entry_offset + 16)[0]
            
            dir_offset = struct.unpack_from('<I', vol_data, vol_entry_offset + 28)[0]
            dir_count = struct.unpack_from('<I', vol_data, vol_entry_offset + 32)[0]

            vol_name_abs = volumes_offset + vol_name_offset
            vol_name = data[vol_name_abs:vol_name_abs + vol_name_len * 2].decode('utf-16-le', errors='ignore').rstrip('\x00')
            vol_time = filetime_to_datetime(vol_create_time)

            vol_info = {
                "path": vol_name,
                "serial": f"{vol_serial:08X}",
                "created": vol_time.strftime('%Y-%m-%d %H:%M:%S UTC') if vol_time else None
            }
            result["volumes"].append(vol_info)
            
            # Parse directories for this volume
            dir_strings_offset = volumes_offset + dir_offset
            pos = dir_strings_offset
            for _ in range(dir_count):
                if pos >= len(data) - 2:
                    break
                dir_len = struct.unpack_from('<H', data, pos)[0]
                pos += 2
                if pos + (dir_len + 1) * 2 > len(data):
                    break
                dir_name = data[pos:pos + dir_len * 2].decode('utf-16-le', errors='ignore')
                pos += (dir_len + 1) * 2
                if dir_name:
                    result["directories"].append(dir_name)

        # Parse file references
        filename_strings = data[filename_offset:filename_offset + filename_size]
        
        for i in range(metrics_count):
            entry_offset = metrics_offset + (i * 32)
            if entry_offset + 32 > len(data):
                break
            
            metric_entry = data[entry_offset:entry_offset + 32]
            start_time, duration, avg_duration, name_offset, name_len, flags, ntfs_ref = struct.unpack('<IIIIIIQ', metric_entry)
            
            try:
                name_data = filename_strings[name_offset:name_offset + 520]
                null_pos = 0
                while null_pos < len(name_data) - 1:
                    if name_data[null_pos:null_pos+2] == b'\x00\x00':
                        break
                    null_pos += 2
                name = name_data[:null_pos].decode('utf-16-le', errors='ignore')
                if name:
                    result["files"].append({
                        "path": name,
                        "ntfs_ref": f"{ntfs_ref:016X}" if ntfs_ref else None
                    })
            except:
                pass

    elif version == 26:  # Windows 8
        # Similar structure but different offsets
        metrics_offset = struct.unpack_from('<I', data, 84)[0]
        metrics_count = struct.unpack_from('<I', data, 88)[0]
        filename_offset = struct.unpack_from('<I', data, 100)[0]
        filename_size = struct.unpack_from('<I', data, 104)[0]
        
        result["run_count"] = struct.unpack_from('<I', data, 124)[0]
        
        for i in range(8):
            ft = struct.unpack_from('<Q', data, 128 + (i * 8))[0]
            if ft:
                dt = filetime_to_datetime(ft)
                if dt:
                    result["last_run_times"].append(dt.strftime('%Y-%m-%d %H:%M:%S UTC'))
        
        filename_strings = data[filename_offset:filename_offset + filename_size]
        for i in range(metrics_count):
            entry_offset = metrics_offset + (i * 32)
            if entry_offset + 32 > len(data):
                break
            name_offset = struct.unpack_from('<I', data, entry_offset + 12)[0]
            try:
                name_data = filename_strings[name_offset:name_offset + 520]
                null_pos = name_data.find(b'\x00\x00')
                if null_pos > 0:
                    name = name_data[:null_pos].decode('utf-16-le', errors='ignore')
                    if name:
                        result["files"].append({"path": name, "ntfs_ref": None})
            except:
                pass

    return result


def print_result(result, show_files=True, show_dirs=False):
    """Pretty print the parsed result"""
    print("=" * 70)
    print(f"PREFETCH ANALYSIS: {result['executable']}")
    print("=" * 70)
    print(f"Source File:      {result['source_file']}")
    print(f"Version:          {result['version']} ({result['version_string']})")
    print(f"Compressed:       {'Yes (MAM/LZXPRESS Huffman)' if result['compressed'] else 'No'}")
    print(f"Prefetch Hash:    {result['hash']}")
    
    print(f"\n--- Execution Info ---")
    print(f"Run Count:        {result['run_count']}")
    
    if result['last_run_times']:
        print(f"\nLast Run Times:")
        for i, t in enumerate(result['last_run_times'], 1):
            print(f"  [{i}] {t}")
    
    if result['volumes']:
        print(f"\n--- Volumes ({len(result['volumes'])}) ---")
        for vol in result['volumes']:
            print(f"  {vol['path']}")
            print(f"    Serial:  {vol['serial']}")
            if vol['created']:
                print(f"    Created: {vol['created']}")
    
    if show_dirs and result['directories']:
        print(f"\n--- Directories ({len(result['directories'])}) ---")
        for d in result['directories'][:50]:
            print(f"  {d}")
        if len(result['directories']) > 50:
            print(f"  ... and {len(result['directories']) - 50} more")
    
    if show_files and result['files']:
        print(f"\n--- Files Referenced ({len(result['files'])}) ---")
        for f in result['files']:
            print(f"  {f['path']}")
    
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Parse Windows 10/11 Prefetch files on Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s NOTEPAD.EXE-12345678.pf
  %(prog)s -d /path/to/prefetch/folder --csv output.csv
  %(prog)s file.pf --json --output result.json
        """
    )
    parser.add_argument("path", help="Prefetch file or directory to parse")
    parser.add_argument("-d", "--directory", action="store_true", 
                        help="Process all .pf files in directory")
    parser.add_argument("--csv", metavar="FILE", help="Output results to CSV file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--output", "-o", metavar="FILE", help="Output file for JSON")
    parser.add_argument("--no-files", action="store_true", help="Don't show file references")
    parser.add_argument("--show-dirs", action="store_true", help="Show directory references")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    
    args = parser.parse_args()
    
    files_to_process = []
    
    if args.directory or os.path.isdir(args.path):
        path = Path(args.path)
        files_to_process = list(path.glob("*.pf")) + list(path.glob("*.PF"))
    else:
        files_to_process = [Path(args.path)]
    
    if not files_to_process:
        print(f"No prefetch files found in {args.path}")
        return 1
    
    results = []
    
    for pf_file in files_to_process:
        try:
            result = parse_prefetch(pf_file)
            results.append(result)
            
            if not args.quiet and not args.json and not args.csv:
                print_result(result, show_files=not args.no_files, show_dirs=args.show_dirs)
                
        except Exception as e:
            print(f"Error parsing {pf_file}: {e}")
    
    # JSON output
    if args.json:
        output = json.dumps(results, indent=2, default=str)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"JSON written to {args.output}")
        else:
            print(output)
    
    # CSV output
    if args.csv:
        with open(args.csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Executable', 'Hash', 'Version', 'RunCount', 
                'LastRun1', 'LastRun2', 'LastRun3', 'FileCount', 'SourceFile'
            ])
            for r in results:
                runs = r['last_run_times'] + [''] * 8
                writer.writerow([
                    r['executable'], r['hash'], r['version_string'], r['run_count'],
                    runs[0], runs[1], runs[2], len(r['files']), r['source_file']
                ])
        print(f"CSV written to {args.csv}")
    
    return 0


if __name__ == "__main__":
    exit(main())