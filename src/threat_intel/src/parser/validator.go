package parser

// =============================================================================
// Validator - INTENTIONALLY EMPTY
// =============================================================================
//
// This file is a placeholder. Validation does NOT belong in the parser layer.
//
// Parser Layer: Read files, detect content types, return raw data
// Processor Layer: Validate, normalize, enrich, insert to database
//
// Why validation is in processor, not parser:
// 1. Parser reads files as-is, returns exactly what's in the file
// 2. Validation rules vary by use case (e.g., private IPs may be valid or invalid)
// 3. Processor knows the context (is this IP for blocking? For geo lookup?)
// 4. Keeping parser simple makes it reusable for any purpose
//
// Content type detection IS provided in parser:
// - txt.go: detectContent() identifies IP, domain, URL, hash
// - csv.go: detectContentType() analyzes field values
// - json.go: analyzes JSON values for content types
//
// These are hints for the processor, not strict validation.
// =============================================================================
