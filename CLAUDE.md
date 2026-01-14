# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python toolkit for analyzing Genetec Security Center federation logs and health events. It provides AI-powered analysis using machine learning algorithms to detect anomalies, predict failures, and generate actionable recommendations for store connectivity issues.

The tools analyze logs from federated Security Center deployments (specifically Starbucks stores with "SBUXSCRoleGroup" federation groups) to identify connection problems, disconnects, and patterns.

## Key Components

### Analyzers - Which Version to Use

**Recommended: analyze_federation_ai.py** (Primary)
- Full-featured AI-powered analysis with anomaly detection, clustering, forecasting
- Best for: Daily analysis, investigations, comprehensive reports
- Run: `python analyze_federation_ai.py [path]`

**For Very Large Datasets: analyze_federation_logs_v3.py**
- Memory-efficient streaming with Welford's algorithm
- Best for: 10M+ lines, constrained memory environments
- Run: `python analyze_federation_logs_v3.py [path]`

**Other Analyzers:**
- **health_events_analyzer.py** - Analyzes Excel health event exports
- **analyze_store_reasons.py** - Focused disconnect reason analysis per store
- **analyze_federation_logs_v2.py** - Optimized v2, faster than v1 (20-30% speed improvement)
- **analyze_federation_logs.py** - Original v1 (legacy, superseded by v2)

### MCP Server
- **federation_mcp_server.py** - Model Context Protocol server exposing analysis tools. Configure in Claude Desktop using the pattern in `claude_desktop_config.example.json`

## Running the Analyzers

```bash
# Install dependencies
pip install -r requirements.txt

# Federation log analysis (auto-discovers in ~/Downloads if no path given)
python analyze_federation_ai.py
python analyze_federation_ai.py /path/to/logs.zip
python analyze_federation_ai.py /path/to/directory/

# Health events analysis
python health_events_analyzer.py
python health_events_analyzer.py "/path/to/Health history.xlsx"
```

## Architecture

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
