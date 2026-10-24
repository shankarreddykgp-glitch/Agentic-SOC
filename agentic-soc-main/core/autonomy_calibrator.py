"""
Dynamic Autonomy Calibration Matrix
Allows SOC operators to adjust the system's autonomy level in real-time,
controlling the threshold boundaries for SOAR enforcement vs HITL review.
DEFCON Autonomy Levels:
  Level 1 (Manual HITL): All events >= 50 risk require analyst approval. No autonomous blocks.
  Level 2 (Conservative): Only events >= 90 risk are auto-blocked. 50-89 require HITL.
  Level 3 (Balanced - Default): Events > 80 auto-blocked. 50-80 require HITL. < 50 monitored.
  Level 4 (Full SOAR): Events >= 50 are auto-blocked. < 50 monitored. Zero HITL pauses.
"""

from typing import Dict, Any, Tuple
import threading


class AutonomyCalibrator:
    """Thread-safe Dynamic Autonomy Calibration Engine."""

    LEVELS = {
        1: {
            "name": "MANUAL HITL",
            "description": "Full human oversight. All events >= 50 risk require analyst approval.",
            "auto_block_threshold": 999.0,  # effectively never auto-blocks
            "hitl_lower_threshold": 50.0,
            "color": "#ffb700",
            "icon": "fa-user-shield"
        },
        2: {
            "name": "CONSERVATIVE",
            "description": "High-confidence auto-blocks only (>=90). Most events routed to HITL.",
            "auto_block_threshold": 90.0,
            "hitl_lower_threshold": 50.0,
            "color": "#00e5ff",
            "icon": "fa-shield-halved"
        },
        3: {
            "name": "BALANCED",
            "description": "Default mode. Auto-blocks >80, HITL review 50-80, monitors <50.",
            "auto_block_threshold": 80.0,
            "hitl_lower_threshold": 50.0,
            "color": "#00ff88",
            "icon": "fa-scale-balanced"
        },
        4: {
            "name": "FULL SOAR",
            "description": "Maximum automation. Auto-blocks >=50. No HITL pauses.",
            "auto_block_threshold": 50.0,
            "hitl_lower_threshold": 50.0,
            "color": "#ff2a5f",
            "icon": "fa-robot"
        }
    }

    def __init__(self, initial_level: int = 3):
        self._lock = threading.Lock()
        self._level = initial_level if initial_level in self.LEVELS else 3

    @property
    def current_level(self) -> int:
        with self._lock:
            return self._level

    @property
    def current_config(self) -> Dict[str, Any]:
        with self._lock:
            return self.LEVELS[self._level].copy()

    def set_level(self, level: int) -> Dict[str, Any]:
        """Set autonomy level (1-4). Returns new config."""
        if level not in self.LEVELS:
            raise ValueError(f"Invalid autonomy level: {level}. Must be 1-4.")
        with self._lock:
            self._level = level
            return {
                "status": "SUCCESS",
                "level": level,
                "config": self.LEVELS[level].copy()
            }

    def get_thresholds(self) -> Tuple[float, float]:
        """Returns (auto_block_threshold, hitl_lower_threshold) for current level."""
        with self._lock:
            cfg = self.LEVELS[self._level]
            return cfg["auto_block_threshold"], cfg["hitl_lower_threshold"]

    def classify_action(self, risk_score: float) -> str:
        """
        Given a risk score, returns the appropriate action string
        based on current autonomy level thresholds.
        """
        auto_thresh, hitl_thresh = self.get_thresholds()
        if risk_score > auto_thresh:
            return "AUTONOMOUS_CRITICAL_BLOCK"
        elif risk_score >= hitl_thresh:
            return "HUMAN_IN_LOOP_REQUIRED"
        else:
            return "AUTONOMOUS_MONITOR"

    def get_status(self) -> Dict[str, Any]:
        """Returns full status info for API/dashboard consumption."""
        with self._lock:
            level = self._level
            cfg = self.LEVELS[level]
            return {
                "current_level": level,
                "level_name": cfg["name"],
                "description": cfg["description"],
                "auto_block_threshold": cfg["auto_block_threshold"],
                "hitl_lower_threshold": cfg["hitl_lower_threshold"],
                "color": cfg["color"],
                "icon": cfg["icon"],
                "all_levels": {k: v["name"] for k, v in self.LEVELS.items()}
            }


# Global singleton instance
autonomy_engine = AutonomyCalibrator(initial_level=3)
