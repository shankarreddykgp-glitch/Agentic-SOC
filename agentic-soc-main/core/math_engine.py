"""
Deterministic Math Engine for Autonomous SOC
Provides exact mathematical functions for detecting token entropy anomalies and impossible travel velocities.
"""

import math
from collections import Counter


def calculate_shannon_entropy(token: str) -> float:
    """
    Calculates the Shannon Entropy H(X) of a session token string.
    Formula: H(X) = - sum( P(x_i) * log2(P(x_i)) )
    Higher entropy indicates random/encrypted/stolen synthetic session cookies.
    Standard threshold: > 3.85 bits per character.
    """
    if not token:
        return 0.0

    length = len(token)
    counts = Counter(token)
    
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_travel_velocity(
    lat1: float, lon1: float, lat2: float, lon2: float, hours: float
) -> float:
    """
    Calculates travel velocity in km/h between two geographical points using the Haversine formula.
    
    Haversine formula:
        a = sin^2(dLat/2) + cos(lat1) * cos(lat2) * sin^2(dLon/2)
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        distance = R * c
    
    Speed = distance (km) / hours
    Flagged as Impossible Travel if velocity > 800 km/h (commercial aircraft speed threshold).
    """
    # Earth radius in kilometers
    R = 6371.0

    # Convert degrees to radians
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    # Haversine formula
    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    distance_km = R * c

    # Prevent division by zero or negative time deltas
    # Minimum time window clamped to 1 second (1/3600 hours = 0.0002777 hours)
    effective_hours = max(hours, 0.0002777)
    
    velocity_kmh = distance_km / effective_hours
    return round(velocity_kmh, 2)



