# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python toolkit for analyzing Genetec Security Center federation logs and health events. It provides AI-powered analysis using machine learning algorithms to detect anomalies, predict failures, and generate actionable recommendations for store connectivity issues.

The tools analyze logs from federated Security Center deployments (specifically Starbucks stores with "SBUXSCRoleGroup" federation groups) to identify connection problems, disconnects, and patterns.

## Key Components

### Analyzers - Which Version to Use

**Recommended: analyze_smart.py** (Auto-Select)
- Automatically chooses the best analyzer based on dataset size, file count, and available memory
- Analyzes dataset profile before running
- Run: `python analyze_smart.py [path]`
- Options: `--dry-run` (analyze only), `--force-ai`, `--force-v2`, `--force-v3`

**Selection Logic:**
| Dataset Size | Files | Analyzer Selected |
|--------------|-------|-------------------|
| <1GB | <500 | AI analyzer (full ML) |
| 1-10GB | 500-2000 | AI or v2 (based on memory) |
| >10GB | >2000 | v3 (streaming) |
| Any | Memory constrained | v3 (streaming) |

**Individual Analyzers (all use multiprocessing for parallel CPU utilization):**
- **analyze_federation_ai.py** - Full AI/ML analysis (Isolation Forest, LOF, clustering, forecasting). Uses ProcessPoolExecutor for file processing. Best for small-medium datasets with sufficient RAM.
- **analyze_federation_logs_v3.py** - Memory-efficient streaming with Welford's algorithm. Uses ProcessPoolExecutor for true parallel processing across all CPU cores. Best for 10GB+, 10M+ lines.
- **analyze_federation_logs_v2.py** - Optimized v2 with ProcessPoolExecutor multiprocessing. Faster than v1 (now 10-20x faster with all CPU cores).
- **analyze_federation_logs.py** - Original v1 (legacy, superseded by v2)

**Other Tools:**
- **health_events_analyzer.py** - Analyzes Excel health event exports
- **analyze_store_reasons.py** - Focused disconnect reason analysis per store

### MCP Server
- **federation_mcp_server.py** - Model Context Protocol server exposing analysis tools. Configure in Claude Desktop using the pattern in `claude_desktop_config.example.json`

## Output Format

**Always generate HTML reports** after running any analyzer. Create a visually appealing HTML file (`federation_report.html`) with:
- Summary stat cards with key metrics
- Interactive Chart.js visualizations (line charts, donut charts, bar charts)
- Styled tables for top problem stores, longest disconnections, etc.
- Dark theme with gradient accents
- Critical incident alerts when applicable
- Open the report in the browser automatically after generation

Example sections to include:
- Daily disconnect trend (line chart)
- Federation group distribution (donut chart)
- Error type breakdown (pie chart)
- Top 20 problem stores (table with visual bars)
- Longest disconnection times (table)
- Peak activity hours (bar chart)

## Running the Analyzers

**File Management Workflow:**
- When working with ZIP files, use `unzip_logs.py` to extract them to `/Volumes/MacMini/temps/claude/templogs`
- The unzip script automatically:
  - Extracts server ID from zip filename (e.g., `MS63870Fed.zip` → server `MS63870`)
  - Creates a subfolder per server: `/templogs/MS63870/`, `/templogs/MS63871/`, etc.
  - Recursively unzips nested zip files (zips inside zips) into the same server folder
  - Handles any number of servers dynamically
- Keep unzipped files in `/Volumes/MacMini/temps/claude/templogs` until a new session with new zip files is started
- Before removing existing log files from `/Volumes/MacMini/temps/claude/templogs`, ask whether the new zip files should:
  - **Add to** existing files (keep old files and add new ones)
  - **Replace** existing files (remove old files before unzipping new ones)

**Server-Aware Analysis:**
- Federation groups (e.g., `SBUXSCRoleGroup6`) have the same names across different servers
- Always separate analysis by server first, then by federation group within each server
- Reports should show per-server breakdowns to avoid mixing data from different infrastructure

```bash
# Install dependencies
pip install -r requirements.txt

# Smart analyzer (recommended) - auto-selects best analyzer
python analyze_smart.py /path/to/logs/
python analyze_smart.py /path/to/logs.zip
python analyze_smart.py /path/to/logs/ --dry-run  # Preview selection only

# Force specific analyzer if needed
python analyze_smart.py /path/to/logs/ --force-ai   # Force AI/ML analyzer
python analyze_smart.py /path/to/logs/ --force-v3   # Force streaming analyzer

# Direct analyzer usage (if you know which one to use)
python analyze_federation_ai.py /path/to/logs/      # Small-medium datasets
python analyze_federation_logs_v3.py /path/to/logs/ # Large datasets (10GB+)

# Health events analysis
python health_events_analyzer.py
python health_events_analyzer.py "/path/to/Health history.xlsx"
```

## Architecture

### Multiprocessing
All analyzers (v2, v3, AI) use `ProcessPoolExecutor` for true parallel processing across all CPU cores. This bypasses Python's Global Interpreter Lock (GIL) limitation that affects `ThreadPoolExecutor`.

**Key implementation details:**
- Worker functions are defined at module level to allow pickle serialization
- Data structures use regular dicts instead of `defaultdict(lambda)` for pickle compatibility
- Results are serialized (timestamps as ISO strings, sets as lists) and merged in the main process
- ZIP files are still processed sequentially due to temp file handling constraints

### ML Algorithms Used
- **Anomaly Detection**: Ensemble of Isolation Forest, Local Outlier Factor (LOF), DBSCAN, and Z-score methods. Anomaly if ≥2 methods agree.
- **Clustering**: K-Means for grouping stores by error behavior patterns
- **Time Series**: STL-style decomposition, Holt-Winters forecasting, CUSUM change point detection
- **Root Cause**: Bayesian inference with prior probabilities for network/hardware/certificate issues

### AI Optimizer Module (ai_optimizer.py)

Advanced ML module providing enhanced anomaly detection and pattern recognition.

**Classes:**
- `EnhancedAnomalyDetector` - Ensemble of Isolation Forest, LOF, One-Class SVM, DBSCAN, and statistical methods (Z-score, IQR, MAD) with weighted voting
- `NeuralPatternRecognizer` - TF-IDF + MLP classifier for error message classification
- `SequenceAnalyzer` - Temporal pattern detection with K-Means clustering and forecasting
- `InternalErrorClassifier` - Random Forest classifier for error type prediction
- `ModelEvaluator` - Cross-validation and performance metrics

**Integration:** Called via `optimize_and_evaluate(store_stats, events, error_totals)` in analyze_federation_ai.py step [8/8].

**Dependencies:** Requires scikit-learn ≥1.3.0, scipy ≥1.11.0 (graceful degradation if unavailable).

### Data Flow
1. Log files parsed for timestamps, store IDs (pattern: `Store[\s_](\d{4,5})`), and error categories
2. Events classified into categories: `tls_handshake_error`, `connection_timeout`, `connection_refused`, `host_unreachable`, `socket_exception`, `proxy_disconnect`, etc.
3. Statistics aggregated per store, per machine, and per hour
4. ML algorithms detect anomalies and patterns
5. Recommendations generated with priority scores

### Key Patterns
- Store ID format: 5-digit normalized (e.g., "51389" or "05139")
- Federation groups: `SBUXSCRoleGroup\d+`
- Timestamp format: `2024-01-04T21:06:38.339-08:00`

## Dependencies

Required: `pandas`, `numpy`, `openpyxl`, `scikit-learn`, `scipy`, `mcp` (for MCP server)

## MCP Server Setup

Add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "federation-analysis": {
      "command": "python",
      "args": ["/full/path/to/federation_mcp_server.py"],
      "env": {"PYTHONPATH": "/full/path/to/federation_log_analysis"}
    }
  }
}
```

Available MCP tools: `analyze_federation_logs`, `analyze_health_events`, `get_anomalous_stores`, `get_store_details`, `get_recommendations`, `get_time_series_forecast`, `get_machine_health`
