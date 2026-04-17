"""
EcoBPF ML Energy Estimation Model

Linear regression model trained on calibrated bare-metal benchmarks
to translate kernel telemetry signals into estimated energy consumption (joules).

Feature vector:
    - cpu_time_ns: CPU time in nanoseconds
    - ctx_switches: Total context switches
    - cpu_freq_mhz: CPU frequency at measurement time
    - major_faults: Major page faults (I/O required)
    - minor_faults: Minor page faults (TLB miss)
    - rss_bytes: Resident Set Size in bytes
    - gpu_active_ns: GPU active time in nanoseconds

Output:
    - energy_joules: Estimated total energy consumption
"""

import os
import numpy as np
import joblib
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS = [
    "cpu_time_ns",
    "ctx_switches",
    "cpu_freq_mhz",
    "major_faults",
    "minor_faults",
    "rss_bytes",
    "gpu_active_ns",
]

# Default model path
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.joblib")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.joblib")


class EnergyEstimator:
    """
    Energy consumption estimator using linear regression.

    Translates kernel telemetry feature vectors into estimated energy
    consumption in joules. Supports per-component energy breakdown
    (CPU, memory, GPU) via learned coefficients.
    """

    def __init__(self, model_path: str = MODEL_PATH, scaler_path: str = SCALER_PATH):
        self.model: LinearRegression | None = None
        self.scaler: StandardScaler | None = None
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model_version = "1.0.0-synthetic"

        # Per-component coefficient indices
        self._cpu_indices = [0, 1, 2]       # cpu_time, ctx_switches, cpu_freq
        self._mem_indices = [3, 4, 5]       # major_faults, minor_faults, rss
        self._gpu_indices = [6]             # gpu_active_ns

    def load(self) -> None:
        """Load the trained model and scaler from disk."""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
        else:
            raise FileNotFoundError(
                f"Model files not found at {self.model_path}. "
                "Run train.py first to generate the model."
            )

    def train(self, X: np.ndarray, y: np.ndarray) -> dict:
        """
        Train the model on calibration data.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Target energy values in joules (n_samples,)

        Returns:
            Training metrics dict with R², MAE, and coefficients.
        """
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = LinearRegression()
        self.model.fit(X_scaled, y)

        # Compute metrics
        y_pred = self.model.predict(X_scaled)
        r2 = self.model.score(X_scaled, y)
        mae = np.mean(np.abs(y - y_pred))

        metrics = {
            "r2_score": r2,
            "mae_joules": mae,
            "coefficients": dict(zip(FEATURE_COLUMNS, self.model.coef_)),
            "intercept": self.model.intercept_,
        }

        return metrics

    def save(self) -> None:
        """Persist the trained model and scaler to disk."""
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

    def predict(self, features: np.ndarray) -> np.ndarray:
        """
        Predict energy consumption for a batch of feature vectors.

        Args:
            features: Shape (n_samples, 7) — one row per process.

        Returns:
            Predicted energy in joules, shape (n_samples,).
        """
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model not loaded. Call load() or train() first.")

        X_scaled = self.scaler.transform(features)
        predictions = self.model.predict(X_scaled)

        # Clamp to non-negative (energy can't be negative)
        return np.maximum(predictions, 0.0)

    def predict_with_breakdown(self, features: np.ndarray) -> list[dict]:
        """
        Predict energy with per-component breakdown.

        Returns a list of dicts with total, cpu, memory, and gpu energy.
        """
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model not loaded. Call load() or train() first.")

        X_scaled = self.scaler.transform(features)
        total = np.maximum(self.model.predict(X_scaled), 0.0)

        # Component breakdown using coefficient attribution
        coefs = self.model.coef_
        results = []

        for i in range(len(features)):
            scaled_row = X_scaled[i]

            cpu_contrib = sum(coefs[j] * scaled_row[j] for j in self._cpu_indices)
            mem_contrib = sum(coefs[j] * scaled_row[j] for j in self._mem_indices)
            gpu_contrib = sum(coefs[j] * scaled_row[j] for j in self._gpu_indices)

            # Normalize to total prediction
            total_contrib = abs(cpu_contrib) + abs(mem_contrib) + abs(gpu_contrib)
            if total_contrib > 0:
                cpu_energy = total[i] * (abs(cpu_contrib) / total_contrib)
                mem_energy = total[i] * (abs(mem_contrib) / total_contrib)
                gpu_energy = total[i] * (abs(gpu_contrib) / total_contrib)
            else:
                cpu_energy = total[i]
                mem_energy = 0.0
                gpu_energy = 0.0

            results.append({
                "energy_joules": float(total[i]),
                "cpu_energy_joules": float(cpu_energy),
                "memory_energy_joules": float(mem_energy),
                "gpu_energy_joules": float(gpu_energy),
            })

        return results

    def get_feature_importance(self) -> dict:
        """Return feature importances (absolute coefficient magnitudes)."""
        if self.model is None:
            return {}

        importances = np.abs(self.model.coef_)
        total = importances.sum()
        if total > 0:
            importances = importances / total

        return dict(zip(FEATURE_COLUMNS, importances))
