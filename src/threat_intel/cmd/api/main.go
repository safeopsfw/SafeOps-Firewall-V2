package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"threat_intel/src/storage"
)

// =============================================================================
// Threat Intel REST API
// =============================================================================
// Endpoints:
//   GET /api/status              - Database status
//   GET /api/lookup/ip/{ip}      - IP lookup
//   GET /api/lookup/domain/{domain} - Domain lookup
//   GET /api/lookup/hash/{hash}  - Hash lookup
//   GET /api/headers             - Table headers
//   GET /api/health              - Health check
// =============================================================================

// CORS middleware wrapper
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func main() {
	log.Println("===========================================")
	log.Println("SafeOps Threat Intel API Server")
	log.Println("===========================================")

	// Routes with CORS
	http.HandleFunc("/api/status", cors(handleStatus))
	http.HandleFunc("/api/lookup/ip/", cors(handleIPLookup))
	http.HandleFunc("/api/lookup/geo/", cors(handleGeoLookup))
	http.HandleFunc("/api/lookup/domain/", cors(handleDomainLookup))
	http.HandleFunc("/api/lookup/hash/", cors(handleHashLookup))
	http.HandleFunc("/api/headers", cors(handleHeaders))
	http.HandleFunc("/api/health", cors(handleHealth))

	log.Println("Starting server on :8080...")
	log.Println("CORS enabled for all origins")
	log.Println("Endpoints:")
	log.Println("  GET /api/status")
	log.Println("  GET /api/lookup/ip/{ip}")
	log.Println("  GET /api/lookup/geo/{ip}")
	log.Println("  GET /api/lookup/domain/{domain}")
	log.Println("  GET /api/lookup/hash/{hash}")
	log.Println("  GET /api/headers")
	log.Println("  GET /api/health")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// handleHealth returns API health status
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// handleStatus returns database row counts
func handleStatus(w http.ResponseWriter, r *http.Request) {
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	tables := []string{"domains", "hashes", "ip_blacklist", "ip_geolocation", "ip_anonymization"}
	status := make(map[string]interface{})

	for _, table := range tables {
		info, err := db.GetTableInfo(table)
		if err == nil && info.Exists {
			status[table] = map[string]interface{}{
				"row_count": info.RowCount,
				"columns":   len(info.Columns),
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleIPLookup checks an IP against all threat tables
func handleIPLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/lookup/ip/")
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	ctx := context.Background()
	result := make(map[string]interface{})
	result["ip"] = ip
	result["found"] = false

	// Check blacklist
	ipStore := storage.NewIPBlacklistStorage(db)
	if rec, err := ipStore.GetByIP(ctx, ip); err == nil && rec != nil {
		result["blacklist"] = rec
		result["found"] = true
	}

	// Check geolocation
	geoStore := storage.NewIPGeoStorage(db)
	if rec, err := geoStore.GetByIP(ctx, ip); err == nil && rec != nil {
		result["geolocation"] = rec
		result["found"] = true
	}

	// Check anonymization
	anonStore := storage.NewIPAnonymizationStorage(db)
	if rec, err := anonStore.GetByIP(ctx, ip); err == nil && rec != nil {
		result["anonymization"] = rec
		result["found"] = true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleGeoLookup returns geolocation for an IP (country, city, ASN, coordinates)
func handleGeoLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/lookup/geo/")
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	ctx := context.Background()
	geoStore := storage.NewIPGeoStorage(db)

	rec, err := geoStore.GetByIP(ctx, ip)

	result := make(map[string]interface{})
	result["ip"] = ip

	if err != nil || rec == nil {
		result["found"] = false
	} else {
		result["found"] = true
		result["country_code"] = rec.CountryCode
		result["country_name"] = rec.CountryName
		result["city"] = rec.City
		result["region"] = rec.Region
		result["latitude"] = rec.Latitude
		result["longitude"] = rec.Longitude
		result["asn"] = rec.ASN
		result["asn_org"] = rec.ASNOrg
		result["isp"] = rec.ISP
		result["timezone"] = rec.Timezone
		result["is_mobile"] = rec.IsMobile
		result["is_hosting"] = rec.IsHosting
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleDomainLookup checks a domain
func handleDomainLookup(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/api/lookup/domain/")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}

	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	ctx := context.Background()
	domainStore := storage.NewDomainStorage(db)

	rec, err := domainStore.GetByDomain(ctx, domain)

	result := make(map[string]interface{})
	result["domain"] = domain

	if err != nil || rec == nil {
		result["found"] = false
	} else {
		result["found"] = true
		result["data"] = rec
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleHashLookup checks a hash
func handleHashLookup(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimPrefix(r.URL.Path, "/api/lookup/hash/")
	if hash == "" {
		http.Error(w, "Hash required", http.StatusBadRequest)
		return
	}

	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	ctx := context.Background()
	hashStore := storage.NewHashStorage(db)

	var rec *storage.HashRecord
	if len(hash) == 64 {
		rec, err = hashStore.GetBySHA256(ctx, hash)
	} else {
		rec, err = hashStore.GetByMD5(ctx, hash)
	}

	result := make(map[string]interface{})
	result["hash"] = hash

	if err != nil || rec == nil {
		result["found"] = false
	} else {
		result["found"] = true
		result["data"] = rec
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleHeaders returns table columns
func handleHeaders(w http.ResponseWriter, r *http.Request) {
	db, err := storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	tables := []string{"domains", "hashes", "ip_blacklist", "ip_geolocation", "ip_anonymization"}
	headers := make(map[string]interface{})

	for _, table := range tables {
		info, err := db.GetTableInfo(table)
		if err == nil && info.Exists {
			cols := make([]map[string]interface{}, len(info.Columns))
			for i, col := range info.Columns {
				cols[i] = map[string]interface{}{
					"name":     col.Name,
					"type":     col.DataType,
					"nullable": col.IsNullable,
				}
			}
			headers[table] = map[string]interface{}{
				"row_count": info.RowCount,
				"columns":   cols,
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(headers)
}
