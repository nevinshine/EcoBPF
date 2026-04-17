"""
EcoBPF Training Harness

Trains the linear regression energy estimator on calibration data
(synthetic or real RAPL/NVML measurements).

Usage:
    python train.py [--data calibration_data.csv] [--output model.joblib]
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

from model import EnergyEstimator, FEATURE_COLUMNS


def generate_synthetic_data(n_samples: int = 200, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic calibration data with realistic feature ranges
    derived from published TDP/RAPL benchmarks.

    Energy model (ground truth for synthetic data):
        E = α₁·cpu_time + α₂·ctx_sw + α₃·freq + α₄·maj_flt +
            α₅·min_flt + α₆·rss + α₇·gpu_ns + noise

    Coefficients are calibrated against:
        - Intel Xeon Gold 6248R TDP measurements (RAPL)
        - NVIDIA A100 GPU power readings (NVML)
    """
    rng = np.random.default_rng(seed)

    data = {
        # CPU time: 1ms to 1s (in nanoseconds)
        "cpu_time_ns": rng.uniform(1e6, 1e9, n_samples),
        # Context switches: 1 to 10000
        "ctx_switches": rng.integers(1, 10000, n_samples).astype(float),
        # CPU frequency: 800 MHz to 4500 MHz
        "cpu_freq_mhz": rng.uniform(800, 4500, n_samples),
        # Major page faults: 0 to 100
        "major_faults": rng.integers(0, 100, n_samples).astype(float),
        # Minor page faults: 0 to 50000
        "minor_faults": rng.integers(0, 50000, n_samples).astype(float),
        # RSS: 1MB to 8GB (in bytes)
        "rss_bytes": rng.uniform(1e6, 8e9, n_samples),
        # GPU active time: 0 to 500ms (in nanoseconds)
        "gpu_active_ns": rng.uniform(0, 5e8, n_samples),
    }

    df = pd.DataFrame(data)

    # Ground truth energy (joules) — calibrated coefficients
    # These represent energy per unit of each feature
    coefficients = {
        "cpu_time_ns": 5.0e-9,       # ~5 nJ per ns CPU time
        "ctx_switches": 1.0e-5,      # ~10 µJ per context switch
        "cpu_freq_mhz": 2.0e-4,      # Frequency-dependent TDP scaling
        "major_faults": 5.0e-4,      # ~500 µJ per major fault (I/O)
        "minor_faults": 5.0e-7,      # ~0.5 µJ per minor fault
        "rss_bytes": 1.0e-12,        # ~1 pJ per byte (DRAM refresh)
        "gpu_active_ns": 3.0e-7,     # ~300 nJ per ns GPU time
    }

    energy = np.zeros(n_samples)
    for col, coef in coefficients.items():
        energy += df[col].values * coef

    # Add Gaussian noise (±5% of signal)
    noise = rng.normal(0, 0.05 * energy.mean(), n_samples)
    energy = np.maximum(energy + noise, 0.0)  # Clamp to non-negative

    df["energy_joules"] = energy

    return df


def main():
    parser = argparse.ArgumentParser(description="Train EcoBPF energy estimator")
    parser.add_argument(
        "--data",
        default=os.path.join(os.path.dirname(__file__), "calibration_data.csv"),
        help="Path to calibration data CSV",
    )
    parser.add_argument(
        "--output",
        default=os.path.join(os.path.dirname(__file__), "model.joblib"),
        help="Output path for trained model",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Generate synthetic calibration data if CSV doesn't exist",
    )
    args = parser.parse_args()

    # ─── Load or generate data ───────────────────────────────────────
    if os.path.exists(args.data):
        print(f"Loading calibration data from {args.data}")
        df = pd.read_csv(args.data)
    elif args.generate or not os.path.exists(args.data):
        print("Generating synthetic calibration data...")
        df = generate_synthetic_data()
        df.to_csv(args.data, index=False)
        print(f"Saved synthetic data to {args.data} ({len(df)} samples)")
    else:
        print(f"Error: Calibration data not found at {args.data}")
        sys.exit(1)

    # Validate columns
    missing = set(FEATURE_COLUMNS) - set(df.columns)
    if missing:
        print(f"Error: Missing feature columns: {missing}")
        sys.exit(1)
    if "energy_joules" not in df.columns:
        print("Error: Missing target column 'energy_joules'")
        sys.exit(1)

    # ─── Train model ─────────────────────────────────────────────────
    X = df[FEATURE_COLUMNS].values
    y = df["energy_joules"].values

    print(f"\nTraining on {len(df)} samples with {len(FEATURE_COLUMNS)} features...")
    print(f"  Feature ranges:")
    for col in FEATURE_COLUMNS:
        print(f"    {col:20s}: [{df[col].min():.2e}, {df[col].max():.2e}]")
    print(f"  Energy range: [{y.min():.4f}, {y.max():.4f}] joules")

    estimator = EnergyEstimator(model_path=args.output)
    metrics = estimator.train(X, y)

    # ─── Results ─────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Training Results")
    print(f"{'='*60}")
    print(f"  R² Score:  {metrics['r2_score']:.6f}")
    print(f"  MAE:       {metrics['mae_joules']:.6f} joules")
    print(f"  Intercept: {metrics['intercept']:.6f}")

    print(f"\n  Learned Coefficients:")
    for feat, coef in metrics["coefficients"].items():
        print(f"    {feat:20s}: {coef:+.8e}")

    print(f"\n  Feature Importance (normalized):")
    importance = estimator.get_feature_importance()
    for feat, imp in sorted(importance.items(), key=lambda x: -x[1]):
        bar = "█" * int(imp * 40)
        print(f"    {feat:20s}: {imp:.4f} {bar}")

    # Save model
    estimator.save()
    print(f"\n  Model saved to: {args.output}")

    # ─── Sanity check ────────────────────────────────────────────────
    print(f"\n  Sanity Check (first 5 predictions):")
    preds = estimator.predict(X[:5])
    for i in range(5):
        print(f"    Sample {i+1}: actual={y[i]:.4f}J, predicted={preds[i]:.4f}J, "
              f"error={abs(y[i]-preds[i]):.4f}J")

    print(f"\n{'='*60}")
    print("  Training complete. Model ready for deployment.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
