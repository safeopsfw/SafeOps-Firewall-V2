package api

import (
	"net/http"
	"threat_intel/config"

	"github.com/gorilla/mux"
)

func NewRouter(cfg *config.Config) http.Handler {
	r := mux.NewRouter()
	h := NewHandlers(cfg)

	// Apply middleware
	r.Use(LoggingMiddleware)
	r.Use(CORSMiddleware)
	r.Use(RateLimitMiddleware)

	// Health check
	r.HandleFunc("/health", h.HealthCheck).Methods("GET")

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/ip/{ip}", h.GetIPReputation).Methods("GET")
	api.HandleFunc("/domain/{domain}", h.GetDomainReputation).Methods("GET")
	api.HandleFunc("/hash/{hash}", h.GetHashReputation).Methods("GET")
	api.HandleFunc("/ioc", h.GetIOCData).Methods("GET")

	return r
}
