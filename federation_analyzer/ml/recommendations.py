"""
Recommendation generation with priority scoring.
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Recommendation:
    """Actionable recommendation with priority scoring."""
    priority: int  # 1-5, 1 being highest
    category: str  # 'immediate', 'short_term', 'preventive'
    target: str  # store_id, machine, or 'system'
    action: str  # specific action to take
    reason: str  # why this action is recommended
    estimated_impact: str  # expected improvement
    confidence: float  # 0-1 confidence score


class RecommendationEngine:
    """
    Generate actionable recommendations with priority scoring.
    """

    def __init__(self):
        self.recommendations = []

    def generate_recommendations(self, analysis_results: Dict) -> List[Recommendation]:
        """
        Generate prioritized recommendations based on analysis results.
        """
        self.recommendations = []

        # Check anomaly detection results
        if 'anomalies' in analysis_results:
            anomalies = analysis_results['anomalies']
            if anomalies.get('anomalous_stores'):
                top_anomalies = anomalies['anomalous_stores'][:5]
                for store in top_anomalies:
                    self.recommendations.append(Recommendation(
                        priority=1,
                        category='immediate',
                        target=f"Store {store['store_id']}",
                        action=f"Investigate connectivity to store {store['store_id']}",
                        reason=f"Anomalous behavior detected: {store['total_errors']:,} errors",
                        estimated_impact=f"Reduce ~{store['total_errors']//2:,} errors",
                        confidence=0.85
                    ))

        # Check cascade detection
        if 'cascades' in analysis_results:
            cascades = analysis_results['cascades']
            if cascades.get('server_wide_cascades', 0) > 0:
                self.recommendations.append(Recommendation(
                    priority=1,
                    category='immediate',
                    target='Federation Servers',
                    action='Review federation server load balancing and health',
                    reason=f"{cascades['server_wide_cascades']} server-wide cascade events detected",
                    estimated_impact='Prevent mass disconnections',
                    confidence=0.9
                ))

        # Check root causes
        if 'root_causes' in analysis_results:
            for cause in analysis_results['root_causes'][:3]:
                if cause['probability'] > 0.2:
                    action = self._get_action_for_cause(cause['cause'])
                    self.recommendations.append(Recommendation(
                        priority=2 if cause['probability'] > 0.3 else 3,
                        category='short_term',
                        target='System',
                        action=action,
                        reason=f"Root cause analysis: {cause['cause']} ({cause['probability']:.0%} probability)",
                        estimated_impact='Address underlying issue',
                        confidence=cause['probability']
                    ))

        # Check predictions
        if 'predictions' in analysis_results:
            pred = analysis_results['predictions']
            if pred.get('trend_direction') == 'increasing':
                self.recommendations.append(Recommendation(
                    priority=2,
                    category='preventive',
                    target='System',
                    action='Scale up monitoring and prepare incident response',
                    reason='Error trend is increasing',
                    estimated_impact='Faster response to incidents',
                    confidence=0.7
                ))

        # Check machine health
        if 'machine_health' in analysis_results:
            for machine, health in analysis_results['machine_health'].items():
                if health.get('score', 100) < 40:
                    self.recommendations.append(Recommendation(
                        priority=1,
                        category='immediate',
                        target=machine,
                        action=f'Review and potentially restart federation services on {machine}',
                        reason=f"Low health score ({health['score']:.0f}/100)",
                        estimated_impact=f"Improve {len(health.get('stores', []))} store connections",
                        confidence=0.8
                    ))

        # Sort by priority
        self.recommendations.sort(key=lambda r: (r.priority, -r.confidence))

        return self.recommendations

    def _get_action_for_cause(self, cause: str) -> str:
        """Get specific action for a root cause."""
        actions = {
            'network_issue': 'Review network routes and firewall rules for store connectivity',
            'store_hardware': 'Schedule maintenance check for affected store vNVR hardware',
            'certificate_expiry': 'Audit and renew TLS certificates across federation',
            'server_overload': 'Rebalance store distribution across federation servers',
            'configuration_error': 'Review recent configuration changes and federation settings',
            'external_dependency': 'Check external service dependencies (DNS, proxy, etc.)'
        }
        return actions.get(cause, 'Investigate further')

    def format_report(self) -> str:
        """Format recommendations as a text report."""
        if not self.recommendations:
            return "No critical recommendations at this time."

        lines = []
        lines.append("=" * 70)
        lines.append("ACTIONABLE RECOMMENDATIONS")
        lines.append("=" * 70)

        current_priority = None
        for rec in self.recommendations:
            if rec.priority != current_priority:
                current_priority = rec.priority
                priority_labels = {1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW', 5: 'INFO'}
                lines.append(f"\n[{priority_labels.get(rec.priority, 'OTHER')} PRIORITY]")
                lines.append("-" * 40)

            lines.append(f"\n  Target: {rec.target}")
            lines.append(f"  Action: {rec.action}")
            lines.append(f"  Reason: {rec.reason}")
            lines.append(f"  Impact: {rec.estimated_impact}")
            lines.append(f"  Confidence: {rec.confidence:.0%}")

        return "\n".join(lines)
