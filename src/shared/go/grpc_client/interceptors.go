// Package grpc_client provides comprehensive gRPC client interceptors for observability and cross-cutting concerns.
package grpc_client

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/safeops/shared/go/errors"
	"github.com/safeops/shared/go/logging"
	"github.com/safeops/shared/go/metrics"
)

// ============================================================================
// Logging Interceptor
// ============================================================================

// LoggingInterceptor creates a logging interceptor for unary RPCs
func LoggingInterceptor(logger *logging.Logger) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		start := time.Now()

		// Call the RPC
		err := invoker(ctx, method, req, reply, cc, opts...)

		duration := time.Since(start)

		if logger != nil {
			if err != nil {
				st, _ := status.FromError(err)
				logger.Error("gRPC call failed",
					"method", method,
					"duration_ms", duration.Milliseconds(),
					"code", st.Code().String(),
					"error", st.Message(),
				)
			} else {
				logger.Info("gRPC call succeeded",
					"method", method,
					"duration_ms", duration.Milliseconds(),
				)
			}
		}

		return err
	}
}

// LoggingStreamInterceptor creates a logging interceptor for streaming RPCs
func LoggingStreamInterceptor(logger *logging.Logger) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		start := time.Now()

		if logger != nil {
			logger.Info("gRPC stream started", "method", method)
		}

		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			if logger != nil {
				logger.Error("gRPC stream failed to start",
					"method", method,
					"error", err.Error(),
				)
			}
			return nil, err
		}

		return &loggingStream{
			ClientStream: stream,
			method:       method,
			startTime:    start,
			logger:       logger,
		}, nil
	}
}

type loggingStream struct {
	grpc.ClientStream
	method    string
	startTime time.Time
	logger    *logging.Logger
}

func (s *loggingStream) RecvMsg(m interface{}) error {
	err := s.ClientStream.RecvMsg(m)
	if err != nil && s.logger != nil {
		duration := time.Since(s.startTime)
		s.logger.Info("gRPC stream completed",
			"method", s.method,
			"duration_ms", duration.Milliseconds(),
		)
	}
	return err
}

// ============================================================================
// Metrics Interceptor
// ============================================================================

// MetricsInterceptor creates a metrics interceptor for unary RPCs
func MetricsInterceptor(metricsReg *metrics.MetricsRegistry) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		start := time.Now()

		// Call the RPC
		err := invoker(ctx, method, req, reply, cc, opts...)

		duration := time.Since(start)
		code := status.Code(err)

		// Record metrics
		if metricsReg != nil {
			// RecordRequest signature: (service, method string, duration time.Duration, status string)
			metricsReg.RecordRequest(method, code.String(), duration, fmt.Sprintf("%dms", duration.Milliseconds()))

			// RecordError signature: (service, errorType string)
			if err != nil {
				metricsReg.RecordError(method, code.String())
			}
		}

		return err
	}
}

// MetricsStreamInterceptor creates a metrics interceptor for streaming RPCs
func MetricsStreamInterceptor(metricsReg *metrics.MetricsRegistry) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		start := time.Now()

		if metricsReg != nil {
			metricsReg.RecordRequest(method, "stream_started", 0*time.Second, "")
		}

		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			if metricsReg != nil {
				metricsReg.RecordError(method, status.Code(err).String())
			}
			return nil, err
		}

		return &metricsStream{
			ClientStream: stream,
			method:       method,
			startTime:    start,
			metricsReg:   metricsReg,
		}, nil
	}
}

type metricsStream struct {
	grpc.ClientStream
	method     string
	startTime  time.Time
	metricsReg *metrics.MetricsRegistry
}

func (s *metricsStream) RecvMsg(m interface{}) error {
	err := s.ClientStream.RecvMsg(m)
	if err != nil && s.metricsReg != nil {
		duration := time.Since(s.startTime)
		code := status.Code(err)
		s.metricsReg.RecordRequest(s.method, code.String(), duration, "stream_completed")
		s.metricsReg.RecordError(s.method, code.String())
	}
	return err
}

// ============================================================================
// Authentication Interceptor
// ============================================================================

// AuthTokenInterceptor creates an interceptor that injects authentication token
func AuthTokenInterceptor(tokenProvider func() string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		token := tokenProvider()
		if token != "" {
			md := metadata.Pairs("authorization", "Bearer "+token)
			ctx = metadata.NewOutgoingContext(ctx, md)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// AuthStreamInterceptor creates an authentication interceptor for streaming RPCs
func AuthStreamInterceptor(tokenProvider func() string) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		token := tokenProvider()
		if token != "" {
			md := metadata.Pairs("authorization", "Bearer "+token)
			ctx = metadata.NewOutgoingContext(ctx, md)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// ============================================================================
// Error Handling Interceptor
// ============================================================================

// ErrorHandlerInterceptor converts gRPC errors to SafeOps errors
func ErrorHandlerInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err != nil {
			return convertGRPCError(err, method)
		}
		return nil
	}
}

// convertGRPCError converts gRPC status codes to SafeOps errors
func convertGRPCError(err error, method string) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	code := st.Code()
	msg := st.Message()

	switch code {
	case codes.NotFound:
		return errors.New("GRPC_NOT_FOUND", fmt.Sprintf("%s: %s", method, msg))
	case codes.AlreadyExists:
		return errors.New("GRPC_ALREADY_EXISTS", fmt.Sprintf("%s: %s", method, msg))
	case codes.PermissionDenied:
		return errors.New("GRPC_PERMISSION_DENIED", fmt.Sprintf("%s: %s", method, msg))
	case codes.Unauthenticated:
		return errors.New("GRPC_UNAUTHENTICATED", fmt.Sprintf("%s: %s", method, msg))
	case codes.InvalidArgument:
		return errors.New("GRPC_INVALID_ARGUMENT", fmt.Sprintf("%s: %s", method, msg))
	case codes.DeadlineExceeded:
		return errors.New("GRPC_DEADLINE_EXCEEDED", fmt.Sprintf("%s: %s", method, msg))
	case codes.Unavailable:
		return errors.New("GRPC_UNAVAILABLE", fmt.Sprintf("%s: %s", method, msg))
	case codes.Unimplemented:
		return errors.New("GRPC_UNIMPLEMENTED", fmt.Sprintf("%s: %s", method, msg))
	case codes.Internal:
		return errors.New("GRPC_INTERNAL_ERROR", fmt.Sprintf("%s: %s", method, msg))
	case codes.Canceled:
		return errors.New("GRPC_CANCELED", fmt.Sprintf("%s: %s", method, msg))
	case codes.ResourceExhausted:
		return errors.New("GRPC_RESOURCE_EXHAUSTED", fmt.Sprintf("%s: %s", method, msg))
	default:
		return errors.Wrap(err, "GRPC_ERROR", fmt.Sprintf("%s failed", method))
	}
}

// ============================================================================
// Timeout Interceptor
// ============================================================================

// TimeoutInterceptor enforces default timeout if context doesn't have deadline
func TimeoutInterceptor(defaultTimeout time.Duration) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// Only set timeout if context doesn't have deadline
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
			defer cancel()
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// ============================================================================
// Tracing Interceptor
// ============================================================================

// TracingInterceptor propagates trace context for distributed tracing
func TracingInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// Extract trace ID from context if present
		traceID := ctx.Value("trace-id")
		if traceID != nil {
			md := metadata.Pairs("x-trace-id", fmt.Sprintf("%v", traceID))
			ctx = metadata.NewOutgoingContext(ctx, md)
		}

		// TODO: Integration with OpenTelemetry/Jaeger when available
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// TracingStreamInterceptor propagates trace context for streaming RPCs
func TracingStreamInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		// Extract trace ID from context if present
		traceID := ctx.Value("trace-id")
		if traceID != nil {
			md := metadata.Pairs("x-trace-id", fmt.Sprintf("%v", traceID))
			ctx = metadata.NewOutgoingContext(ctx, md)
		}

		return streamer(ctx, desc, cc, method, opts...)
	}
}

// ============================================================================
// Request ID Interceptor
// ============================================================================

// RequestIDInterceptor adds request ID to all RPCs
func RequestIDInterceptor(generator func() string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		requestID := generator()
		md := metadata.Pairs("x-request-id", requestID)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// ============================================================================
// Recovery Interceptor
// ============================================================================

// RecoveryInterceptor recovers from panics in RPC handlers
func RecoveryInterceptor(logger *logging.Logger) grpc.UnaryClientInterceptor {
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
				if logger != nil {
					logger.Error("gRPC panic recovered",
						"method", method,
						"panic", r,
					)
				}
				err = status.Errorf(codes.Internal, "internal panic: %v", r)
			}
		}()

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// ============================================================================
// Interceptor Chaining
// ============================================================================

// ChainUnaryInterceptors chains multiple unary interceptors
// Interceptors execute in order: first interceptor wraps the second, etc.
func ChainUnaryInterceptors(interceptors ...grpc.UnaryClientInterceptor) grpc.UnaryClientInterceptor {
	if len(interceptors) == 0 {
		return func(ctx context.Context, method string, req, reply interface{},
			cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
	}

	return func(ctx context.Context, method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		chain := invoker

		// Build chain in reverse order
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := chain
			chain = func(ctx context.Context, method string, req, reply interface{},
				cc *grpc.ClientConn, opts ...grpc.CallOption) error {
				return interceptor(ctx, method, req, reply, cc, next, opts...)
			}
		}

		return chain(ctx, method, req, reply, cc, opts...)
	}
}

// ChainStreamInterceptors chains multiple stream interceptors
func ChainStreamInterceptors(interceptors ...grpc.StreamClientInterceptor) grpc.StreamClientInterceptor {
	if len(interceptors) == 0 {
		return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
			method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return streamer(ctx, desc, cc, method, opts...)
		}
	}

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
		method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		chain := streamer

		// Build chain in reverse order
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := chain
			chain = func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
				method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
				return interceptor(ctx, desc, cc, method, next, opts...)
			}
		}

		return chain(ctx, desc, cc, method, opts...)
	}
}

// ============================================================================
// Helper: Build Default Interceptors
// ============================================================================

// DefaultInterceptors returns commonly used interceptors
func DefaultInterceptors(logger *logging.Logger, metricsReg *metrics.MetricsRegistry) ([]grpc.UnaryClientInterceptor, []grpc.StreamClientInterceptor) {
	unary := []grpc.UnaryClientInterceptor{
		RecoveryInterceptor(logger),
		TimeoutInterceptor(10 * time.Second),
		TracingInterceptor(),
		LoggingInterceptor(logger),
		MetricsInterceptor(metricsReg),
		ErrorHandlerInterceptor(),
	}

	stream := []grpc.StreamClientInterceptor{
		TracingStreamInterceptor(),
		LoggingStreamInterceptor(logger),
		MetricsStreamInterceptor(metricsReg),
	}

	return unary, stream
}
