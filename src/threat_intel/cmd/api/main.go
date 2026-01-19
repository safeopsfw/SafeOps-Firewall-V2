package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"threat_intel/src/storage"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

const PORT = ":5050"

var db *storage.DB

func main() {
	log.Println("==========================================")
	log.Println("SafeOps Threat Intel API Server")
	log.Println("==========================================")

	// Connect to database
	var err error
	db, err = storage.NewDB(storage.DefaultDBConfig())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("[OK] Connected to PostgreSQL")

	// Setup router
	r := mux.NewRouter()
	api := r.PathPrefix("/api/threat-intel").Subrouter()

	// Routes
	api.HandleFunc("/health", healthHandler).Methods("GET")
	api.HandleFunc("/status", statusHandler).Methods("GET")
	api.HandleFunc("/headers", headersHandler).Methods("GET")
	api.HandleFunc("/lookup/ip/{ip}", lookupIPHandler).Methods("GET")
	api.HandleFunc("/lookup/domain/{domain}", lookupDomainHandler).Methods("GET")
	api.HandleFunc("/lookup/hash/{hash}", lookupHashHandler).Methods("GET")
	api.HandleFunc("/update", triggerUpdateHandler).Methods("POST")

	// CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)

	log.Printf("Starting API server on http://localhost%s", PORT)
	log.Printf("Endpoints available at http://localhost%s/api/threat-intel/", PORT)
	log.Fatal(http.ListenAndServe(PORT, handler))
}

// Health check
func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "online",
		"service": "threat-intel-api",
	})
}

// Get database status (row counts)
func statusHandler(w http.ResponseWriter, r *http.Request) {
	tables := []string{"domains", "hashes", "ip_blacklist", "ip_geolocation", "ip_anonymization"}
	status := make(map[string]interface{})

	for _, table := range tables {
		info, err := db.GetTableInfo(table)
		if err == nil && info.Exists {
			status[table] = map[string]interface{}{
				"count":   info.RowCount,
				"exists":  true,
				"columns": len(info.Columns),
			}
		} else {
			status[table] = map[string]interface{}{
				"count":  0,
				"exists": false,
			}
		}
	}

	json.NewEncoder(w).Encode(status)
}

// Get table headers/columns
func headersHandler(w http.ResponseWriter, r *http.Request) {
	tables := []string{"domains", "hashes", "ip_blacklist", "ip_geolocation", "ip_anonymization"}
	headers := make(map[string]interface{})

	for _, table := range tables {
		info, err := db.GetTableInfo(table)
		if err == nil && info.Exists {
			cols := []map[string]interface{}{}
			for _, col := range info.Columns {
				cols = append(cols, map[string]interface{}{
					"name":       col.Name,
					"type":       col.DataType,
					"isNullable": col.IsNullable,
				})
			}
			headers[table] = cols
		}
	}

	json.NewEncoder(w).Encode(headers)
}

// Lookup IP
func lookupIPHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ip := vars["ip"]
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

	json.NewEncoder(w).Encode(result)
}

// Lookup Domain
func lookupDomainHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := strings.ToLower(vars["domain"])
	ctx := context.Background()

	result := make(map[string]interface{})
	result["domain"] = domain
	result["found"] = false

	domainStore := storage.NewDomainStorage(db)
	if rec, err := domainStore.GetByDomain(ctx, domain); err == nil && rec != nil {
		result["record"] = rec
		result["found"] = true
	}

	json.NewEncoder(w).Encode(result)
}

// Lookup Hash
func lookupHashHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash := strings.ToLower(vars["hash"])
	ctx := context.Background()

	result := make(map[string]interface{})
	result["hash"] = hash
	result["found"] = false

	hashStore := storage.NewHashStorage(db)
	var rec *storage.HashRecord
	var err error

	if len(hash) == 64 {
		rec, err = hashStore.GetBySHA256(ctx, hash)
	} else {
		rec, err = hashStore.GetByMD5(ctx, hash)
	}

	if err == nil && rec != nil {
		result["record"] = rec
		result["found"] = true
	}

	json.NewEncoder(w).Encode(result)
}

// Trigger database update (run pipeline)
func triggerUpdateHandler(w http.ResponseWriter, r *http.Request) {
	// This would trigger the pipeline in background
	// For now, just return success
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "triggered",
		"message": "Database update started in background",
	})
}
