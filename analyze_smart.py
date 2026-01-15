#!/usr/bin/env python3
"""
Smart Federation Log Analyzer Selector

Automatically chooses the best analyzer based on:
- Dataset size (total bytes)
- File count
- Available system memory
- File complexity (nested ZIPs vs flat logs)

Decision Matrix:
- Small (<1GB, <500 files): AI analyzer - full ML analysis
- Medium (1-10GB, 500-2000 files): v2 analyzer - balanced speed/features
- Large (>10GB or >2000 files): v3 analyzer - memory-efficient streaming
"""

import os
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class DatasetProfile:
    """Profile of the dataset to analyze."""

    total_size_bytes: int
    total_files: int
    log_files: int
    zip_files: int
    nested_zip_files: int
    estimated_uncompressed_size: int
    federation_files: int
    available_memory_bytes: int

    @property
    def total_size_gb(self) -> float:
        return self.total_size_bytes / (1024**3)

    @property
    def estimated_size_gb(self) -> float:
        return self.estimated_uncompressed_size / (1024**3)

    @property
    def available_memory_gb(self) -> float:
        return self.available_memory_bytes / (1024**3)

    @property
    def complexity_score(self) -> float:
        """Score 0-1 indicating dataset complexity."""
        score = 0.0
        # Nested ZIPs add complexity
        if self.zip_files > 0:
            score += 0.2
        if self.nested_zip_files > 0:
            score += 0.3
        # High file count adds complexity
        if self.total_files > 1000:
            score += 0.2
        if self.total_files > 5000:
            score += 0.2
        # Large size adds complexity
        if self.total_size_gb > 10:
            score += 0.1
        return min(score, 1.0)


def get_available_memory() -> int:
    """Get available system memory in bytes."""
    try:
        # macOS
        result = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split("\n")
            page_size = 16384  # Default macOS page size
            free_pages = 0
            for line in lines:
                if "page size" in line.lower():
                    try:
                        page_size = int(line.split()[-2])
                    except (ValueError, IndexError):
                        pass
                elif "Pages free" in line:
                    try:
                        free_pages += int(line.split()[-1].rstrip("."))
                    except (ValueError, IndexError):
                        pass
                elif "Pages inactive" in line:
                    try:
                        free_pages += int(line.split()[-1].rstrip("."))
                    except (ValueError, IndexError):
                        pass
            return free_pages * page_size
    except Exception:
        pass

    try:
        # Linux fallback
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass

    # Default: assume 8GB available
    return 8 * 1024**3


def estimate_zip_uncompressed_size(zip_path: str) -> int:
    """Estimate uncompressed size of a ZIP file."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            return sum(info.file_size for info in zf.infolist())
    except Exception:
        # Estimate: compressed files typically 5-10x smaller
        return os.path.getsize(zip_path) * 7


def count_nested_zips(zip_path: str) -> int:
    """Count nested ZIP files inside a ZIP."""
    count = 0
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".zip"):
                    count += 1
    except Exception:
        pass
    return count


def profile_dataset(path: str) -> DatasetProfile:
    """Analyze dataset and return its profile."""
    total_size = 0
    total_files = 0
    log_files = 0
    zip_files = 0
    nested_zip_files = 0
    estimated_uncompressed = 0
    federation_files = 0

    if os.path.isfile(path):
        total_size = os.path.getsize(path)
        total_files = 1
        if path.endswith(".zip"):
            zip_files = 1
            estimated_uncompressed = estimate_zip_uncompressed_size(path)
            nested_zip_files = count_nested_zips(path)
        elif path.endswith(".log"):
            log_files = 1
            estimated_uncompressed = total_size
        if "Federation" in path or "SBUXSCRoleGroup" in path:
            federation_files = 1

    elif os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for f in files:
                full_path = os.path.join(root, f)
                try:
                    file_size = os.path.getsize(full_path)
                    total_size += file_size
                    total_files += 1

                    if f.endswith(".zip"):
                        zip_files += 1
                        estimated_uncompressed += estimate_zip_uncompressed_size(full_path)
                        nested_zip_files += count_nested_zips(full_path)
                    elif f.endswith(".log"):
                        log_files += 1
                        estimated_uncompressed += file_size

                    if "Federation" in f or "SBUXSCRoleGroup" in f:
                        federation_files += 1
                except OSError:
                    pass

    return DatasetProfile(
        total_size_bytes=total_size,
        total_files=total_files,
        log_files=log_files,
        zip_files=zip_files,
        nested_zip_files=nested_zip_files,
        estimated_uncompressed_size=estimated_uncompressed or total_size,
        federation_files=federation_files,
        available_memory_bytes=get_available_memory(),
    )


def select_analyzer(profile: DatasetProfile) -> Tuple[str, str, List[str]]:
    """
    Select the best analyzer based on dataset profile.

    Returns: (analyzer_script, reason, warnings)
    """
    warnings = []

    size_gb = profile.total_size_gb
    estimated_gb = profile.estimated_size_gb
    file_count = profile.total_files
    memory_gb = profile.available_memory_gb

    # Calculate memory requirement estimate
    # AI analyzer: ~10-20 bytes per log line stored, plus ML overhead
    # Estimate ~100 bytes per event in memory
    estimated_events = profile.estimated_uncompressed_size // 200  # ~200 bytes per log line avg
    estimated_memory_needed_gb = (estimated_events * 100) / (1024**3)  # 100 bytes per event

    # Decision tree

    # Check for extremely large datasets first
    if estimated_gb > 50 or file_count > 10000:
        reason = (
            f"Very large dataset ({estimated_gb:.1f}GB estimated, {file_count:,} files). "
            f"Using v3 (streaming) for memory efficiency."
        )
        if estimated_gb > 100:
            warnings.append(
                f"WARNING: Dataset is very large ({estimated_gb:.1f}GB). "
                f"Analysis may take several hours."
            )
        return "analyze_federation_logs_v3.py", reason, warnings

    # Check memory constraints
    if estimated_memory_needed_gb > memory_gb * 0.7:
        reason = (
            f"Dataset may require ~{estimated_memory_needed_gb:.1f}GB memory, "
            f"but only {memory_gb:.1f}GB available. Using v3 (streaming) to avoid OOM."
        )
        warnings.append("Memory constraint detected. Consider closing other applications.")
        return "analyze_federation_logs_v3.py", reason, warnings

    # Large datasets (>10GB or >2000 files)
    if size_gb > 10 or file_count > 2000:
        reason = (
            f"Large dataset ({size_gb:.1f}GB, {file_count:,} files). "
            f"Using v3 (streaming) for optimal performance."
        )
        return "analyze_federation_logs_v3.py", reason, warnings

    # Medium datasets (1-10GB or 500-2000 files)
    if size_gb > 1 or file_count > 500:
        # Check if we have enough memory for AI analyzer
        if estimated_memory_needed_gb < memory_gb * 0.5:
            reason = (
                f"Medium dataset ({size_gb:.1f}GB, {file_count:,} files) with sufficient memory. "
                f"Using AI analyzer for full ML analysis."
            )
            warnings.append("AI analysis may take 10-30 minutes for this dataset size.")
            return "analyze_federation_ai.py", reason, warnings
        else:
            reason = (
                f"Medium dataset ({size_gb:.1f}GB, {file_count:,} files). "
                f"Using v2 for balanced speed and features."
            )
            return "analyze_federation_logs_v2.py", reason, warnings

    # Small datasets (<1GB, <500 files) - use AI analyzer
    reason = (
        f"Small dataset ({size_gb:.2f}GB, {file_count} files). "
        f"Using AI analyzer for comprehensive ML-powered analysis."
    )
    return "analyze_federation_ai.py", reason, warnings


def print_profile(profile: DatasetProfile):
    """Print dataset profile summary."""
    print("\n" + "=" * 60)
    print("DATASET ANALYSIS")
    print("=" * 60)
    print(f"  Total size:          {profile.total_size_gb:.2f} GB")
    print(f"  Estimated unpacked:  {profile.estimated_size_gb:.2f} GB")
    print(f"  Total files:         {profile.total_files:,}")
    print(f"  Log files:           {profile.log_files:,}")
    print(f"  ZIP files:           {profile.zip_files:,}")
    print(f"  Nested ZIPs:         {profile.nested_zip_files:,}")
    print(f"  Federation files:    {profile.federation_files:,}")
    print(f"  Complexity score:    {profile.complexity_score:.2f}")
    print(f"  Available memory:    {profile.available_memory_gb:.1f} GB")
    print("=" * 60)


def main():
    """Main entry point."""
    print("Smart Federation Log Analyzer")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage: python analyze_smart.py <path> [--dry-run]")
        print("\nOptions:")
        print("  --dry-run    Only analyze dataset, don't run analyzer")
        print("  --force-ai   Force AI analyzer regardless of size")
        print("  --force-v2   Force v2 analyzer")
        print("  --force-v3   Force v3 analyzer")
        print("\nExamples:")
        print("  python analyze_smart.py /path/to/logs/")
        print("  python analyze_smart.py ~/Downloads/FedLogs.zip")
        print("  python analyze_smart.py /path/to/logs/ --dry-run")
        sys.exit(1)

    path = os.path.expanduser(sys.argv[1])
    dry_run = "--dry-run" in sys.argv
    force_ai = "--force-ai" in sys.argv
    force_v2 = "--force-v2" in sys.argv
    force_v3 = "--force-v3" in sys.argv

    if not os.path.exists(path):
        print(f"Error: Path not found: {path}")
        sys.exit(1)

    print(f"\nAnalyzing: {path}")
    print("Please wait...")

    # Profile the dataset
    profile = profile_dataset(path)
    print_profile(profile)

    # Handle forced analyzer selection
    if force_ai:
        analyzer = "analyze_federation_ai.py"
        reason = "Forced AI analyzer via --force-ai flag"
        warnings = ["WARNING: AI analyzer forced on potentially large dataset"]
    elif force_v2:
        analyzer = "analyze_federation_logs_v2.py"
        reason = "Forced v2 analyzer via --force-v2 flag"
        warnings = []
    elif force_v3:
        analyzer = "analyze_federation_logs_v3.py"
        reason = "Forced v3 analyzer via --force-v3 flag"
        warnings = []
    else:
        # Auto-select based on profile
        analyzer, reason, warnings = select_analyzer(profile)

    print(f"\nSELECTED ANALYZER: {analyzer}")
    print(f"Reason: {reason}")

    for warning in warnings:
        print(f"\n{warning}")

    if dry_run:
        print("\n[DRY RUN] Would execute:")
        print(f"  python3 {analyzer} {path}")
        sys.exit(0)

    # Confirm before running on large datasets
    if profile.total_size_gb > 20:
        print(f"\nLarge dataset detected ({profile.total_size_gb:.1f}GB).")
        response = input("Continue with analysis? [y/N]: ").strip().lower()
        if response != "y":
            print("Aborted.")
            sys.exit(0)

    # Run the selected analyzer
    print(f"\n{'=' * 60}")
    print(f"RUNNING: {analyzer}")
    print("=" * 60 + "\n")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    analyzer_path = os.path.join(script_dir, analyzer)

    if not os.path.exists(analyzer_path):
        print(f"Error: Analyzer not found: {analyzer_path}")
        sys.exit(1)

    # Execute the analyzer
    result = subprocess.run([sys.executable, analyzer_path, path], cwd=script_dir)

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
