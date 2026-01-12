#!/usr/bin/env python3
"""
MCP Server for Federation Log and Health Events Analysis.

Exposes AI-powered analysis tools for:
- Federation logs (from ZIP files or direct .log files)
- Health events (from Excel spreadsheets)

Tools provided:
- analyze_federation_logs: Analyze federation log files for errors and patterns
- analyze_health_events: Analyze health event Excel files
- get_store_analysis: Get detailed analysis for a specific store
- get_anomalous_stores: Get list of stores with anomalous behavior
- get_recommendations: Get actionable recommendations from analysis
"""

import os
import sys
import json
import asyncio
from typing import Any
from datetime import datetime

# MCP SDK imports
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    CallToolResult,
)

# Import analyzers
from health_events_analyzer import HealthEventsAnalyzer
from analyze_federation_ai import FederationLogAnalyzer

# Global analyzer instances (cached for performance)
_health_analyzer = None
_federation_analyzer = None


def get_health_analyzer() -> HealthEventsAnalyzer:
    """Get or create health events analyzer instance."""
    global _health_analyzer
    if _health_analyzer is None:
        _health_analyzer = HealthEventsAnalyzer()
    return _health_analyzer


def get_federation_analyzer() -> FederationLogAnalyzer:
    """Get or create federation log analyzer instance."""
    global _federation_analyzer
    if _federation_analyzer is None:
        _federation_analyzer = FederationLogAnalyzer()
    return _federation_analyzer


def reset_analyzers():
    """Reset analyzer instances for fresh analysis."""
    global _health_analyzer, _federation_analyzer
    _health_analyzer = None
    _federation_analyzer = None


# Create MCP server
server = Server("federation-analysis")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available analysis tools."""
    return [
        Tool(
            name="analyze_federation_logs",
            description="""Analyze federation log files for connection errors, patterns, and anomalies.

Supports:
- ZIP files containing nested log files
- Direct .log files (unzipped)
- Directories containing log files

Performs advanced ML analysis including:
- Ensemble anomaly detection (Isolation Forest, LOF, DBSCAN)
- Store clustering by error behavior
- Time series analysis and forecasting
- Cascade failure detection
- Root cause analysis with Bayesian inference

Returns comprehensive analysis with actionable recommendations.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to ZIP file, .log file, or directory containing logs. If not provided, searches ~/Downloads for federation log files."
                    },
                    "reset": {
                        "type": "boolean",
                        "description": "Reset analyzer state before processing (default: true for fresh analysis)",
                        "default": True
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="analyze_health_events",
            description="""Analyze health events from Excel spreadsheets exported from Genetec Security Center.

Performs advanced ML analysis including:
- Ensemble anomaly detection for stores
- Store clustering by failure patterns
- Time series decomposition and forecasting
- Pattern recognition (bursts, correlations)
- Root cause analysis

Returns comprehensive analysis with actionable recommendations.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to Excel file (.xlsx). If not provided, searches ~/Downloads for 'Health history*.xlsx' files."
                    },
                    "reset": {
                        "type": "boolean",
                        "description": "Reset analyzer state before processing (default: true)",
                        "default": True
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="get_anomalous_stores",
            description="""Get list of stores detected as anomalous by the ML algorithms.

Must run analyze_federation_logs or analyze_health_events first.
Returns stores ranked by anomaly confidence score.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "analyzer_type": {
                        "type": "string",
                        "enum": ["federation", "health"],
                        "description": "Which analyzer's results to retrieve"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of stores to return (default: 20)",
                        "default": 20
                    }
                },
                "required": ["analyzer_type"]
            }
        ),
        Tool(
            name="get_store_details",
            description="""Get detailed analysis for a specific store.

Returns error counts, patterns, timestamps, and recommendations for the store.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "store_id": {
                        "type": "string",
                        "description": "Store ID (e.g., '51389' or '05139')"
                    },
                    "analyzer_type": {
                        "type": "string",
                        "enum": ["federation", "health"],
                        "description": "Which analyzer's data to query"
                    }
                },
                "required": ["store_id", "analyzer_type"]
            }
        ),
        Tool(
            name="get_recommendations",
            description="""Get actionable recommendations from the analysis.

Returns prioritized list of recommendations with:
- Priority level (1=Critical, 2=High, 3=Medium)
- Target (store, machine, or system)
- Specific action to take
- Reason and confidence score""",
            inputSchema={
                "type": "object",
                "properties": {
                    "analyzer_type": {
                        "type": "string",
                        "enum": ["federation", "health"],
                        "description": "Which analyzer's recommendations to retrieve"
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Filter by priority level (1-3). Omit for all priorities.",
                        "minimum": 1,
                        "maximum": 3
                    }
                },
                "required": ["analyzer_type"]
            }
        ),
        Tool(
            name="get_time_series_forecast",
            description="""Get time series analysis and forecast for error rates.

Returns:
- Current trend (increasing/decreasing/stable)
- 24-hour forecast with confidence intervals
- Peak and low hours
- Change points detected""",
            inputSchema={
                "type": "object",
                "properties": {
                    "analyzer_type": {
                        "type": "string",
                        "enum": ["federation", "health"],
                        "description": "Which analyzer's time series to retrieve"
                    }
                },
                "required": ["analyzer_type"]
            }
        ),
        Tool(
            name="get_machine_health",
            description="""Get health scores for federation machines/servers.

Returns health score (0-100) for each machine with:
- Error counts
- Store counts
- Error/store ratio
- Status (Critical/Warning/Fair/Good)

Only available for federation log analysis.""",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    """Handle tool calls."""

    try:
        if name == "analyze_federation_logs":
            return await analyze_federation_logs(arguments)
        elif name == "analyze_health_events":
            return await analyze_health_events(arguments)
        elif name == "get_anomalous_stores":
            return await get_anomalous_stores(arguments)
        elif name == "get_store_details":
            return await get_store_details(arguments)
        elif name == "get_recommendations":
            return await get_recommendations(arguments)
        elif name == "get_time_series_forecast":
            return await get_time_series_forecast(arguments)
        elif name == "get_machine_health":
            return await get_machine_health(arguments)
        else:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {name}")]
            )
    except Exception as e:
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {str(e)}")]
        )


async def analyze_federation_logs(arguments: dict) -> CallToolResult:
    """Analyze federation log files."""
    import io
    import sys

    path = arguments.get("path")
    reset = arguments.get("reset", True)

    if reset:
        reset_analyzers()

    analyzer = get_federation_analyzer()

    # Capture output
    old_stdout = sys.stdout
    sys.stdout = captured = io.StringIO()

    try:
        if path:
            path = os.path.expanduser(path)
            if os.path.isfile(path):
                if path.endswith('.zip'):
                    analyzer.process_nested_zip(path)
                elif path.endswith('.log'):
                    analyzer.process_log_file(path)
                else:
                    return CallToolResult(
                        content=[TextContent(type="text", text=f"Unsupported file type: {path}")]
                    )
            elif os.path.isdir(path):
                analyzer.process_log_directory(path)
            else:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Path not found: {path}")]
                )
        else:
            # Auto-discover in Downloads
            downloads = os.path.expanduser("~/Downloads")
            found = False

            for f in os.listdir(downloads):
                full_path = os.path.join(downloads, f)
                if f.endswith('.zip') and ('Fed' in f or 'Base' in f):
                    analyzer.process_nested_zip(full_path)
                    found = True
                elif f.endswith('.log') and ('SBUXSCRoleGroup' in f or 'Federation' in f):
                    analyzer.process_log_file(full_path)
                    found = True

            if not found:
                return CallToolResult(
                    content=[TextContent(type="text", text="No federation log files found in ~/Downloads")]
                )

        # Run analysis
        if analyzer.events:
            results = analyzer.generate_report()

            # Store results for later queries
            analyzer._last_results = results

            output = captured.getvalue()

            # Create summary
            summary = {
                "status": "success",
                "files_processed": analyzer.files_processed,
                "lines_processed": analyzer.lines_processed,
                "unique_stores": len(analyzer.store_stats),
                "unique_machines": len(analyzer.machine_stats),
                "total_events": len(analyzer.events),
                "anomalous_stores": len(results.get('anomalies', {}).get('anomalous_stores', [])),
                "cascade_events": len(results.get('cascades', {}).get('cascades', [])),
                "recommendations_count": len(results.get('recommendations', []))
            }

            return CallToolResult(
                content=[
                    TextContent(type="text", text=f"Analysis Summary:\n{json.dumps(summary, indent=2)}\n\nFull Report:\n{output}")
                ]
            )
        else:
            return CallToolResult(
                content=[TextContent(type="text", text="No federation events found in the log files.")]
            )
    finally:
        sys.stdout = old_stdout


async def analyze_health_events(arguments: dict) -> CallToolResult:
    """Analyze health events from Excel."""
    import io
    import sys

    path = arguments.get("path")
    reset = arguments.get("reset", True)

    if reset:
        reset_analyzers()

    analyzer = get_health_analyzer()

    # Capture output
    old_stdout = sys.stdout
    sys.stdout = captured = io.StringIO()

    try:
        if path:
            path = os.path.expanduser(path)
        else:
            # Auto-discover in Downloads
            downloads = os.path.expanduser("~/Downloads")
            health_files = [f for f in os.listdir(downloads)
                          if f.startswith("Health history") and f.endswith(".xlsx")]
            if health_files:
                health_files.sort(key=lambda f: os.path.getmtime(os.path.join(downloads, f)), reverse=True)
                path = os.path.join(downloads, health_files[0])
            else:
                return CallToolResult(
                    content=[TextContent(type="text", text="No 'Health history*.xlsx' files found in ~/Downloads")]
                )

        if not os.path.exists(path):
            return CallToolResult(
                content=[TextContent(type="text", text=f"File not found: {path}")]
            )

        if analyzer.load_excel(path):
            results = analyzer.generate_report()

            # Store results for later queries
            analyzer._last_results = results

            output = captured.getvalue()

            # Create summary
            summary = {
                "status": "success",
                "file": os.path.basename(path),
                "unique_stores": len(analyzer.store_data),
                "unique_machines": len(analyzer.machine_data),
                "time_periods": len(analyzer.hourly_failures),
                "total_failures": sum(d['total_failures'] for d in analyzer.store_data.values()),
                "anomalous_stores": len(results.get('anomalies', {}).get('stores', [])),
                "recommendations_count": len(results.get('recommendations', []))
            }

            return CallToolResult(
                content=[
                    TextContent(type="text", text=f"Analysis Summary:\n{json.dumps(summary, indent=2)}\n\nFull Report:\n{output}")
                ]
            )
        else:
            return CallToolResult(
                content=[TextContent(type="text", text="Failed to load Excel file.")]
            )
    finally:
        sys.stdout = old_stdout


async def get_anomalous_stores(arguments: dict) -> CallToolResult:
    """Get list of anomalous stores."""
    analyzer_type = arguments.get("analyzer_type")
    limit = arguments.get("limit", 20)

    if analyzer_type == "federation":
        analyzer = get_federation_analyzer()
        if not hasattr(analyzer, '_last_results'):
            return CallToolResult(
                content=[TextContent(type="text", text="No analysis results. Run analyze_federation_logs first.")]
            )
        anomalies = analyzer._last_results.get('anomalies', {}).get('anomalous_stores', [])
    else:
        analyzer = get_health_analyzer()
        if not hasattr(analyzer, '_last_results'):
            return CallToolResult(
                content=[TextContent(type="text", text="No analysis results. Run analyze_health_events first.")]
            )
        anomalies = analyzer._last_results.get('anomalies', {}).get('stores', [])

    # Limit results
    anomalies = anomalies[:limit]

    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(anomalies, indent=2, default=str))]
    )


async def get_store_details(arguments: dict) -> CallToolResult:
    """Get detailed analysis for a specific store."""
    store_id = arguments.get("store_id", "").zfill(5)
    analyzer_type = arguments.get("analyzer_type")

    if analyzer_type == "federation":
        analyzer = get_federation_analyzer()
        if store_id not in analyzer.store_stats:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Store {store_id} not found in analysis.")]
            )

        stats = analyzer.store_stats[store_id]
        details = {
            "store_id": store_id,
            "total_errors": stats['total_errors'],
            "error_categories": dict(stats['error_categories']),
            "ips": list(stats['ips']),
            "fed_groups": list(stats['fed_groups']),
            "machines": list(stats['machines']),
            "hourly_counts": {str(k): v for k, v in list(stats['hourly_counts'].items())[-24:]},
            "reconnect_delays": stats['reconnect_delays'][-10:] if stats['reconnect_delays'] else []
        }
    else:
        analyzer = get_health_analyzer()
        if store_id not in analyzer.store_data:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Store {store_id} not found in analysis.")]
            )

        data = analyzer.store_data[store_id]
        details = {
            "store_id": store_id,
            "total_failures": data['total_failures'],
            "avg_daily_failures": data['avg_daily_failures'],
            "failure_variance": data['failure_variance'],
            "peak_hour_failures": data['peak_hour_failures'],
            "night_ratio": data['night_ratio'],
            "weekend_ratio": data['weekend_ratio'],
            "machine": data['machine']
        }

    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(details, indent=2, default=str))]
    )


async def get_recommendations(arguments: dict) -> CallToolResult:
    """Get actionable recommendations."""
    analyzer_type = arguments.get("analyzer_type")
    priority_filter = arguments.get("priority")

    if analyzer_type == "federation":
        analyzer = get_federation_analyzer()
    else:
        analyzer = get_health_analyzer()

    if not hasattr(analyzer, '_last_results'):
        return CallToolResult(
            content=[TextContent(type="text", text=f"No analysis results. Run analyze_{analyzer_type}_{'logs' if analyzer_type == 'federation' else 'events'} first.")]
        )

    recommendations = analyzer._last_results.get('recommendations', [])

    if priority_filter:
        recommendations = [r for r in recommendations if r.get('priority') == priority_filter]

    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(recommendations, indent=2, default=str))]
    )


async def get_time_series_forecast(arguments: dict) -> CallToolResult:
    """Get time series analysis and forecast."""
    analyzer_type = arguments.get("analyzer_type")

    if analyzer_type == "federation":
        analyzer = get_federation_analyzer()
    else:
        analyzer = get_health_analyzer()

    if not hasattr(analyzer, '_last_results'):
        return CallToolResult(
            content=[TextContent(type="text", text=f"No analysis results. Run analysis first.")]
        )

    time_series = analyzer._last_results.get('time_series', {})

    # Convert numpy arrays to lists for JSON serialization
    if 'forecast' in time_series and isinstance(time_series['forecast'], dict):
        forecast = time_series['forecast']
        for key in ['forecast', 'lower_bound', 'upper_bound']:
            if key in forecast and hasattr(forecast[key], 'tolist'):
                forecast[key] = forecast[key].tolist()

    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(time_series, indent=2, default=str))]
    )


async def get_machine_health(arguments: dict) -> CallToolResult:
    """Get machine health scores (federation only)."""
    analyzer = get_federation_analyzer()

    if not hasattr(analyzer, '_last_results'):
        return CallToolResult(
            content=[TextContent(type="text", text="No analysis results. Run analyze_federation_logs first.")]
        )

    machine_health = analyzer._last_results.get('machine_health', {})

    # Format for output
    formatted = {}
    for machine, health in machine_health.items():
        formatted[machine] = {
            "score": health.get('score', 0),
            "errors": health.get('errors', 0),
            "stores_count": len(health.get('stores', [])),
            "status": "Critical" if health.get('score', 0) < 30 else
                     "Warning" if health.get('score', 0) < 50 else
                     "Fair" if health.get('score', 0) < 70 else "Good"
        }

    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(formatted, indent=2))]
    )


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
