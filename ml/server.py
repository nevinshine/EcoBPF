"""
EcoBPF ML gRPC Inference Server

Serves the energy estimation model over gRPC for consumption by
the Go user-space daemon. Uses generated protobuf stubs from estimator.proto.

Usage:
    python server.py [--port 50051] [--model model.joblib]
"""

import argparse
import os
import sys
import time
import signal
import logging
from concurrent import futures

import numpy as np
import grpc
from grpc_reflection.v1alpha import reflection

# Add parent directory for proto imports
sys.path.insert(0, os.path.dirname(__file__))

from proto import estimator_pb2
from proto import estimator_pb2_grpc
from model import EnergyEstimator, FEATURE_COLUMNS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("ecobpf.ml")


class EstimatorServicer(estimator_pb2_grpc.EstimatorServiceServicer):
    """
    gRPC servicer implementing the EstimatorService defined in estimator.proto.
    Deserializes FeatureVectorBatch, runs ML inference, returns EnergyEstimateBatch.
    """

    def __init__(self, model_path: str, carbon_intensity: float = 475.0):
        self.estimator = EnergyEstimator(model_path=model_path)
        self.carbon_intensity = carbon_intensity  # gCO2/kWh
        self.start_time = time.time()
        self.total_inferences = 0

        # Load the model
        try:
            self.estimator.load()
            logger.info(
                "Model loaded successfully (version: %s)",
                self.estimator.model_version,
            )
        except FileNotFoundError:
            logger.warning("Model not found, training on synthetic data...")
            self._train_default_model()

    def _train_default_model(self):
        """Train on synthetic data as fallback."""
        from train import generate_synthetic_data

        df = generate_synthetic_data()
        X = df[FEATURE_COLUMNS].values
        y = df["energy_joules"].values
        metrics = self.estimator.train(X, y)
        self.estimator.save()
        logger.info("Fallback model trained (R²=%.4f)", metrics["r2_score"])

    def Estimate(self, request, context):
        """
        Process a FeatureVectorBatch and return EnergyEstimateBatch.
        """
        start = time.monotonic_ns()

        vectors = request.vectors
        n = len(vectors)
        if n == 0:
            return estimator_pb2.EnergyEstimateBatch(
                inference_latency_ns=0,
                model_version=self.estimator.model_version,
            )

        # Build feature matrix from proto messages
        X = np.zeros((n, len(FEATURE_COLUMNS)))
        for i, fv in enumerate(vectors):
            X[i, 0] = float(fv.cpu_time_ns)
            X[i, 1] = float(fv.ctx_switches)
            X[i, 2] = float(fv.cpu_freq_mhz)
            X[i, 3] = float(fv.major_faults)
            X[i, 4] = float(fv.minor_faults)
            X[i, 5] = float(fv.rss_bytes)
            X[i, 6] = float(fv.gpu_active_ns)

        # Run inference with component breakdown
        results = self.estimator.predict_with_breakdown(X)

        # Build response proto
        estimates = []
        for i, result in enumerate(results):
            fv = vectors[i]
            energy_kwh = result["energy_joules"] / 3.6e6
            carbon_grams = energy_kwh * self.carbon_intensity

            est = estimator_pb2.EnergyEstimate(
                pid=fv.pid,
                comm=fv.comm,
                container_id=fv.container_id,
                energy_joules=result["energy_joules"],
                power_watts=result["energy_joules"],  # 1s collection window
                confidence=0.85,
                cpu_energy_joules=result["cpu_energy_joules"],
                memory_energy_joules=result["memory_energy_joules"],
                gpu_energy_joules=result["gpu_energy_joules"],
                carbon_grams_co2=carbon_grams,
                is_ai_inference=self._is_ai_workload(fv.comm),
            )
            estimates.append(est)

        inference_ns = time.monotonic_ns() - start
        self.total_inferences += n

        logger.debug(
            "Batch inference: %d samples in %.2f ms",
            n,
            inference_ns / 1e6,
        )

        return estimator_pb2.EnergyEstimateBatch(
            estimates=estimates,
            inference_latency_ns=inference_ns,
            model_version=self.estimator.model_version,
        )

    def HealthCheck(self, request, context):
        """Return service health status."""
        return estimator_pb2.HealthResponse(
            healthy=self.estimator.model is not None,
            model_version=self.estimator.model_version,
            uptime_seconds=int(time.time() - self.start_time),
            total_inferences=self.total_inferences,
        )

    @staticmethod
    def _is_ai_workload(comm: str) -> bool:
        """Heuristic check for AI/ML process names."""
        ai_patterns = {
            "python", "python3", "torch", "tensorflow",
            "triton", "onnxruntime", "trtexec", "nvidia-smi",
            "ollama", "vllm", "mlserver", "bentoml",
        }
        return comm in ai_patterns


def main():
    parser = argparse.ArgumentParser(description="EcoBPF ML inference server")
    parser.add_argument("--port", type=int, default=50051, help="gRPC listen port")
    parser.add_argument(
        "--model",
        default=os.path.join(os.path.dirname(__file__), "model.joblib"),
        help="Path to trained model",
    )
    parser.add_argument(
        "--carbon-intensity",
        type=float,
        default=475.0,
        help="Carbon intensity factor (gCO2/kWh)",
    )
    args = parser.parse_args()

    # Initialize servicer
    servicer = EstimatorServicer(
        model_path=args.model,
        carbon_intensity=args.carbon_intensity,
    )

    # Create gRPC server
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=[
            ("grpc.max_receive_message_length", 16 * 1024 * 1024),
            ("grpc.max_send_message_length", 16 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30000),
            ("grpc.keepalive_timeout_ms", 10000),
        ],
    )

    # Register servicer
    estimator_pb2_grpc.add_EstimatorServiceServicer_to_server(servicer, server)

    # Enable server reflection for grpcurl / grpc_cli discovery
    service_names = (
        estimator_pb2.DESCRIPTOR.services_by_name["EstimatorService"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, server)

    # Bind and start
    server.add_insecure_port(f"0.0.0.0:{args.port}")
    server.start()
    logger.info("gRPC server listening on port %d", args.port)

    # Log health status
    health = servicer.HealthCheck(estimator_pb2.HealthRequest(), None)
    logger.info(
        "Service ready: model_version=%s, healthy=%s",
        health.model_version,
        health.healthy,
    )

    # Handle graceful shutdown
    def shutdown_handler(signum, frame):
        logger.info("Shutdown signal received (signal=%d)", signum)
        server.stop(grace=5)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    server.wait_for_termination()


if __name__ == "__main__":
    main()
