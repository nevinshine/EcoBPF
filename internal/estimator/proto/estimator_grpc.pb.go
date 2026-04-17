package proto

import (
	"context"

	"google.golang.org/grpc"
)

type EstimatorServiceClient interface {
	Estimate(ctx context.Context, in *FeatureVectorBatch, opts ...grpc.CallOption) (*EnergyEstimateBatch, error)
}

type estimatorServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewEstimatorServiceClient(cc grpc.ClientConnInterface) EstimatorServiceClient {
	return &estimatorServiceClient{cc}
}

func (c *estimatorServiceClient) Estimate(ctx context.Context, in *FeatureVectorBatch, opts ...grpc.CallOption) (*EnergyEstimateBatch, error) {
	out := new(EnergyEstimateBatch)
	err := c.cc.Invoke(ctx, "/ecobpf.estimator.v1.EstimatorService/Estimate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}
