#!/usr/bin/env python3
"""
AI-Powered Federation Log Analyzer for Genetec Security Center
Enhanced with Advanced ML Algorithms for Pattern Detection and Prediction.

This is the main entry point script. The implementation has been modularized
into the federation_analyzer package for better organization and maintainability.

Features:
- Advanced Anomaly Detection: Isolation Forest, DBSCAN, LOF, Ensemble methods
- Predictive Analytics: ARIMA-style forecasting, trend extrapolation
- Root Cause Inference: Feature importance, causal analysis, Bayesian inference
- Cascade Failure Detection: Temporal correlation, propagation analysis
- Actionable Recommendations: Priority-scored remediation steps

Supports:
- Nested ZIP files containing .log files
- SBUXSCRoleGroup and Federation role logs
- Connection timeout, TLS errors, socket exceptions detection
"""

import os
import sys

# Import from the modular package
from federation_analyzer import FederationLogAnalyzer

# Re-export patterns for backward compatibility
from federation_analyzer import (
    TIMESTAMP_PATTERN,
    STORE_PATTERN,
    IP_PORT_PATTERN,
    FED_GROUP_PATTERN,
    ERROR_PATTERNS,
    INTERNAL_ERROR_SUBTYPES,
    SEVERITY_PATTERNS,
    FederationEvent,
    OnlineStats,
    AdvancedAnomalyDetector,
    PredictiveAnalytics,
    CausalAnalyzer,
    CascadeDetector,
    Recommendation,
    RecommendationEngine,
)


def main():
    """Main entry point."""
    print("Federation Log AI Analyzer")
    print("=" * 50)

    analyzer = FederationLogAnalyzer()

    # Check for command line arguments
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            path = os.path.expanduser(arg)
            if os.path.isfile(path):
                if path.endswith('.zip'):
                    analyzer.process_nested_zip(path)
                elif path.endswith('.log'):
                    analyzer.process_log_file(path)
                else:
                    print(f"Unsupported file type: {path}")
            elif os.path.isdir(path):
                analyzer.process_log_directory(path)
            else:
                print(f"Path not found: {path}")
    else:
        # Auto-discover files in Downloads
        downloads = os.path.expanduser("~/Downloads")
        zip_files = []
        log_files = []

        for f in os.listdir(downloads):
            full_path = os.path.join(downloads, f)
            if f.endswith('.zip') and ('Fed' in f or 'Base' in f):
                zip_files.append(full_path)
            elif f.endswith('.log') and ('SBUXSCRoleGroup' in f or 'Federation' in f):
                log_files.append(full_path)

        if not zip_files and not log_files:
            print("No federation log files found in ~/Downloads")
            print("Looking for: *Fed*.zip, *Base*.zip, *SBUXSCRoleGroup*.log, *Federation*.log")
            print("\nUsage: python analyze_federation_ai.py [file.zip|file.log|directory] ...")
            sys.exit(1)

        # Sort by modification time (newest first)
        zip_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)

        if zip_files:
            print(f"\nFound {len(zip_files)} ZIP files:")
            for f in zip_files:
                size_mb = os.path.getsize(f) / (1024 * 1024)
                print(f"  {os.path.basename(f)} ({size_mb:.1f} MB)")

        if log_files:
            print(f"\nFound {len(log_files)} log files:")
            for f in log_files:
                size_mb = os.path.getsize(f) / (1024 * 1024)
                print(f"  {os.path.basename(f)} ({size_mb:.1f} MB)")

        for zip_file in zip_files:
            analyzer.process_nested_zip(zip_file)

        for log_file in log_files:
            analyzer.process_log_file(log_file)

    if analyzer.events:
        analyzer.generate_report()
    else:
        print("\nNo federation events found in the log files.")


if __name__ == "__main__":
    main()
