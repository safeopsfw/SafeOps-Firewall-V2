// Package grpc_client provides gRPC interceptors.
package grpc_client

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// LoggingInterceptor logs all RPC calls
func LoggingInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)
		duration := time.Since(start)

		if err != nil {
			st, _ := status.FromError(err)
			log.Printf("gRPC %s - %s - %v - %s", method, duration, st.Code(), st.Message())
		} else {
			log.Printf("gRPC %s - %s - OK", method, duration)
		}

		return err
	}
}

// LoggingStreamInterceptor logs streaming calls
func LoggingStreamInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		log.Printf("gRPC Stream %s - started", method)
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			log.Printf("gRPC Stream %s - error: %v", method, err)
		}
		return stream, err
	}
}

// TimeoutInterceptor adds timeout to calls
func TimeoutInterceptor(timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// MetadataInterceptor adds metadata to calls
func MetadataInterceptor(md metadata.MD) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// AuthTokenInterceptor adds authorization token
func AuthTokenInterceptor(token string) grpc.UnaryClientInterceptor {
	return MetadataInterceptor(metadata.Pairs("authorization", "Bearer "+token))
}

// RequestIDInterceptor adds request ID to calls
func RequestIDInterceptor(generator func() string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		md := metadata.Pairs("x-request-id", generator())
		ctx = metadata.AppendToOutgoingContext(ctx, md.Get("x-request-id")...)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// MetricsInterceptor collects metrics
type MetricsInterceptor struct {
	RequestCount  int64
	ErrorCount    int64
	TotalDuration time.Duration
}

// NewMetricsInterceptor creates a metrics interceptor
func NewMetricsInterceptor() *MetricsInterceptor {
	return &MetricsInterceptor{}
}

// Unary returns the unary interceptor
func (m *MetricsInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		start := time.Now()
		m.RequestCount++

		err := invoker(ctx, method, req, reply, cc, opts...)

		m.TotalDuration += time.Since(start)
		if err != nil {
			m.ErrorCount++
		}

		return err
	}
}

// ChainUnaryInterceptors chains multiple interceptors
func ChainUnaryInterceptors(interceptors ...grpc.UnaryClientInterceptor) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		chain := invoker

		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := chain
			chain = func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
				return interceptor(ctx, method, req, reply, cc, next, opts...)
			}
		}

		return chain(ctx, method, req, reply, cc, opts...)
	}
}

// RecoveryInterceptor recovers from panics
func RecoveryInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("gRPC panic recovered: %v", r)
				err = status.Errorf(13, "internal error: %v", r) // codes.Internal
			}
		}()

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
