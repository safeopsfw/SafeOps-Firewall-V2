// Package bindings provides low-level Go bindings to Windows Filtering Platform (WFP) APIs.
package bindings

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// ============================================================================
// WFP DLL Loading
// ============================================================================
// Windows Filtering Platform APIs are provided by fwpuclnt.dll.
// We use syscall.LazyDLL for safe, on-demand loading.

var (
	// fwpuclnt.dll - Windows Filtering Platform User-mode Client
	fwpuclntDLL = syscall.NewLazyDLL("fwpuclnt.dll")

	// Session Management
	procFwpmEngineOpen0      = fwpuclntDLL.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0     = fwpuclntDLL.NewProc("FwpmEngineClose0")
	procFwpmEngineGetOption0 = fwpuclntDLL.NewProc("FwpmEngineGetOption0")
	procFwpmEngineSetOption0 = fwpuclntDLL.NewProc("FwpmEngineSetOption0")

	// Transaction Management
	procFwpmTransactionBegin0  = fwpuclntDLL.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0 = fwpuclntDLL.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0  = fwpuclntDLL.NewProc("FwpmTransactionAbort0")

	// Filter Management
	procFwpmFilterAdd0               = fwpuclntDLL.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0        = fwpuclntDLL.NewProc("FwpmFilterDeleteById0")
	procFwpmFilterDeleteByKey0       = fwpuclntDLL.NewProc("FwpmFilterDeleteByKey0")
	procFwpmFilterGetById0           = fwpuclntDLL.NewProc("FwpmFilterGetById0")
	procFwpmFilterGetByKey0          = fwpuclntDLL.NewProc("FwpmFilterGetByKey0")
	procFwpmFilterCreateEnumHandle0  = fwpuclntDLL.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0              = fwpuclntDLL.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHandle0 = fwpuclntDLL.NewProc("FwpmFilterDestroyEnumHandle0")

	// Provider Management
	procFwpmProviderAdd0         = fwpuclntDLL.NewProc("FwpmProviderAdd0")
	procFwpmProviderDeleteByKey0 = fwpuclntDLL.NewProc("FwpmProviderDeleteByKey0")
	procFwpmProviderGetByKey0    = fwpuclntDLL.NewProc("FwpmProviderGetByKey0")

	// Sublayer Management
	procFwpmSubLayerAdd0         = fwpuclntDLL.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0 = fwpuclntDLL.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmSubLayerGetByKey0    = fwpuclntDLL.NewProc("FwpmSubLayerGetByKey0")

	// Memory Free (for WFP-allocated structures)
	procFwpmFreeMemory0 = fwpuclntDLL.NewProc("FwpmFreeMemory0")
)

// ============================================================================
// WFP Handle Type
// ============================================================================

// Handle represents a WFP engine handle.
// This is returned by FwpmEngineOpen0 and used for all subsequent operations.
type Handle syscall.Handle

// InvalidHandle represents an invalid WFP handle.
const InvalidHandle Handle = 0

// IsValid returns true if the handle is valid.
func (h Handle) IsValid() bool {
	return h != InvalidHandle
}

// ============================================================================
// WFP Engine Manager
// ============================================================================

// Engine manages the WFP engine session and provides high-level operations.
type Engine struct {
	handle  Handle
	session *FWPM_SESSION0
	mu      sync.RWMutex
	isOpen  bool
	inTxn   bool

	// Tracking installed objects
	providers *GUIDSet
	sublayers *GUIDSet
	filters   *GUIDMap
}

// NewEngine creates a new WFP engine instance.
// Call Open() to establish connection to WFP.
func NewEngine() *Engine {
	return &Engine{
		handle:    InvalidHandle,
		isOpen:    false,
		inTxn:     false,
		providers: NewGUIDSet(),
		sublayers: NewGUIDSet(),
		filters:   NewGUIDMap(),
	}
}

// ============================================================================
// Engine Session Management
// ============================================================================

// Open opens a connection to the WFP engine.
// Must be called before any filter operations.
func (e *Engine) Open(session *FWPM_SESSION0) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isOpen {
		return fmt.Errorf("engine already open")
	}

	// Check elevation
	elevated, err := CheckElevated()
	if err != nil {
		return fmt.Errorf("failed to check elevation: %w", err)
	}
	if !elevated {
		return ErrNotElevated
	}

	// Use default session if none provided
	if session == nil {
		session = NewDynamicSession()
	}
	e.session = session

	// Call FwpmEngineOpen0 with NULL session for simplicity
	// NULL session creates a non-dynamic session with default settings
	// This is sufficient for most use cases and avoids struct layout issues
	var handle Handle
	ret, _, _ := procFwpmEngineOpen0.Call(
		0,                                // serverName (null = local)
		uintptr(0xFFFFFFFF),              // authnService (RPC_C_AUTHN_DEFAULT = -1)
		0,                                // authIdentity (null = current user)
		0,                                // session (null = default non-dynamic session)
		uintptr(unsafe.Pointer(&handle)), // engineHandle (out)
	)

	if ret != 0 {
		return NewWFPError(HRESULT(ret), "FwpmEngineOpen0")
	}

	e.handle = handle
	e.isOpen = true

	return nil
}

// Close closes the WFP engine connection.
// All dynamic filters are automatically deleted if session was dynamic.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return nil
	}

	// If in transaction, abort it first
	if e.inTxn {
		e.abortTxnLocked()
	}

	// Call FwpmEngineClose0
	ret, _, _ := procFwpmEngineClose0.Call(uintptr(e.handle))
	if ret != 0 {
		return NewWFPError(HRESULT(ret), "FwpmEngineClose0")
	}

	e.handle = InvalidHandle
	e.isOpen = false
	e.providers.Clear()
	e.sublayers.Clear()
	e.filters.Clear()

	return nil
}

// IsOpen returns true if the engine is connected.
func (e *Engine) IsOpen() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isOpen
}

// Handle returns the raw WFP handle (use with caution).
func (e *Engine) Handle() Handle {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.handle
}

// ============================================================================
// Transaction Management
// ============================================================================

// BeginTransaction starts a WFP transaction.
// All filter operations within the transaction are atomic.
func (e *Engine) BeginTransaction() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}
	if e.inTxn {
		return NewWFPError(FWP_E_TXN_IN_PROGRESS, "BeginTransaction")
	}

	ret, _, _ := procFwpmTransactionBegin0.Call(
		uintptr(e.handle),
		0, // flags (0 = read/write transaction)
	)

	if ret != 0 {
		return NewWFPError(HRESULT(ret), "FwpmTransactionBegin0")
	}

	e.inTxn = true
	return nil
}

// CommitTransaction commits the current transaction.
func (e *Engine) CommitTransaction() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}
	if !e.inTxn {
		return NewWFPError(FWP_E_NO_TXN_IN_PROGRESS, "CommitTransaction")
	}

	ret, _, _ := procFwpmTransactionCommit0.Call(uintptr(e.handle))
	if ret != 0 {
		return NewWFPError(HRESULT(ret), "FwpmTransactionCommit0")
	}

	e.inTxn = false
	return nil
}

// AbortTransaction aborts the current transaction.
func (e *Engine) AbortTransaction() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}
	if !e.inTxn {
		return nil // No transaction to abort
	}

	return e.abortTxnLocked()
}

func (e *Engine) abortTxnLocked() error {
	ret, _, _ := procFwpmTransactionAbort0.Call(uintptr(e.handle))
	e.inTxn = false
	if ret != 0 {
		return NewWFPError(HRESULT(ret), "FwpmTransactionAbort0")
	}
	return nil
}

// InTransaction returns true if a transaction is in progress.
func (e *Engine) InTransaction() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.inTxn
}

// WithTransaction executes a function within a transaction.
// Commits on success, aborts on error.
func (e *Engine) WithTransaction(fn func() error) error {
	if err := e.BeginTransaction(); err != nil {
		return err
	}

	if err := fn(); err != nil {
		_ = e.AbortTransaction()
		return err
	}

	return e.CommitTransaction()
}

// ============================================================================
// Provider Management
// ============================================================================

// AddProvider registers a provider with WFP.
func (e *Engine) AddProvider(provider *FWPM_PROVIDER0) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}

	// Build native provider struct
	nativeProvider, providerSlices, err := e.buildNativeProvider(provider)
	if err != nil {
		return fmt.Errorf("failed to build provider: %w", err)
	}
	defer KeepAliveMany(providerSlices...)

	ret, _, _ := procFwpmProviderAdd0.Call(
		uintptr(e.handle),
		uintptr(unsafe.Pointer(nativeProvider)),
		0, // securityDescriptor (null = default)
	)

	if ret != 0 {
		hr := HRESULT(ret)
		if hr == FWP_E_ALREADY_EXISTS {
			// Provider already exists, that's okay
			e.providers.Add(provider.ProviderKey)
			return nil
		}
		return NewWFPError(hr, "FwpmProviderAdd0")
	}

	e.providers.Add(provider.ProviderKey)
	return nil
}

// DeleteProvider removes a provider from WFP.
func (e *Engine) DeleteProvider(key GUID) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}

	ret, _, _ := procFwpmProviderDeleteByKey0.Call(
		uintptr(e.handle),
		uintptr(unsafe.Pointer(&key)),
	)

	if ret != 0 {
		hr := HRESULT(ret)
		if hr == FWP_E_PROVIDER_NOT_FOUND || hr == FWP_E_NOT_FOUND {
			e.providers.Remove(key)
			return nil
		}
		return NewWFPError(hr, "FwpmProviderDeleteByKey0")
	}

	e.providers.Remove(key)
	return nil
}

// ============================================================================
// Sublayer Management
// ============================================================================

// AddSublayer registers a sublayer with WFP.
func (e *Engine) AddSublayer(sublayer *FWPM_SUBLAYER0) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}

	// Build native sublayer struct
	nativeSublayer, sublayerSlices, err := e.buildNativeSublayer(sublayer)
	if err != nil {
		return fmt.Errorf("failed to build sublayer: %w", err)
	}
	defer KeepAliveMany(sublayerSlices...)

	ret, _, _ := procFwpmSubLayerAdd0.Call(
		uintptr(e.handle),
		uintptr(unsafe.Pointer(nativeSublayer)),
		0, // securityDescriptor (null = default)
	)

	if ret != 0 {
		hr := HRESULT(ret)
		if hr == FWP_E_ALREADY_EXISTS {
			e.sublayers.Add(sublayer.SublayerKey)
			return nil
		}
		return NewWFPError(hr, "FwpmSubLayerAdd0")
	}

	e.sublayers.Add(sublayer.SublayerKey)
	return nil
}

// DeleteSublayer removes a sublayer from WFP.
func (e *Engine) DeleteSublayer(key GUID) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}

	ret, _, _ := procFwpmSubLayerDeleteByKey0.Call(
		uintptr(e.handle),
		uintptr(unsafe.Pointer(&key)),
	)

	if ret != 0 {
		hr := HRESULT(ret)
		if hr == FWP_E_SUBLAYER_NOT_FOUND || hr == FWP_E_NOT_FOUND {
			e.sublayers.Remove(key)
			return nil
		}
		return NewWFPError(hr, "FwpmSubLayerDeleteByKey0")
	}

	e.sublayers.Remove(key)
	return nil
}

// ============================================================================
// Filter Management
// ============================================================================

// AddFilter adds a filter to WFP.
// Returns the filter ID assigned by Windows.
func (e *Engine) AddFilter(filter *FWPM_FILTER0) (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return 0, ErrSessionNotOpen
	}

	// Validate filter
	if err := filter.Validate(); err != nil {
		return 0, fmt.Errorf("invalid filter: %w", err)
	}

	// Generate filter key if not set
	if filter.FilterKey.IsNull() {
		key, err := NewGUID()
		if err != nil {
			return 0, fmt.Errorf("failed to generate filter key: %w", err)
		}
		filter.FilterKey = key
	}

	// Build native filter struct
	nativeFilter, filterSlices, err := e.buildNativeFilter(filter)
	if err != nil {
		return 0, fmt.Errorf("failed to build filter: %w", err)
	}
	defer KeepAliveMany(filterSlices...)

	var filterID uint64
	ret, _, _ := procFwpmFilterAdd0.Call(
		uintptr(e.handle),
		uintptr(unsafe.Pointer(nativeFilter)),
		0, // securityDescriptor (null = default)
		uintptr(unsafe.Pointer(&filterID)),
	)

	if ret != 0 {
		return 0, NewWFPError(HRESULT(ret), "FwpmFilterAdd0")
	}

	// Track the filter
	if filter.RuleID != "" {
		e.filters.Set(filter.RuleID, filter.FilterKey)
	}
	filter.FilterID = filterID

	return filterID, nil
}

// DeleteFilterByKey removes a filter by its GUID key.
func (e *Engine) DeleteFilterByKey(key GUID) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}

	ret, _, _ := procFwpmFilterDeleteByKey0.Call(
		uintptr(e.handle),
		uintptr(unsafe.Pointer(&key)),
	)

	if ret != 0 {
		hr := HRESULT(ret)
		if hr == FWP_E_FILTER_NOT_FOUND || hr == FWP_E_NOT_FOUND {
			return nil // Already deleted
		}
		return NewWFPError(hr, "FwpmFilterDeleteByKey0")
	}

	return nil
}

// DeleteFilterByID removes a filter by its numeric ID.
func (e *Engine) DeleteFilterByID(filterID uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isOpen {
		return ErrSessionNotOpen
	}

	ret, _, _ := procFwpmFilterDeleteById0.Call(
		uintptr(e.handle),
		uintptr(filterID),
	)

	if ret != 0 {
		hr := HRESULT(ret)
		if hr == FWP_E_FILTER_NOT_FOUND || hr == FWP_E_NOT_FOUND {
			return nil
		}
		return NewWFPError(hr, "FwpmFilterDeleteById0")
	}

	return nil
}

// DeleteFilterByRuleID removes a filter by SafeOps rule ID.
func (e *Engine) DeleteFilterByRuleID(ruleID string) error {
	e.mu.Lock()
	key, found := e.filters.Get(ruleID)
	e.mu.Unlock()

	if !found {
		return nil // Not tracked
	}

	err := e.DeleteFilterByKey(key)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.filters.Delete(ruleID)
	e.mu.Unlock()

	return nil
}

// ============================================================================
// Batch Filter Operations
// ============================================================================

// AddFilters adds multiple filters in a single transaction.
func (e *Engine) AddFilters(filters []*FWPM_FILTER0) ([]uint64, error) {
	if len(filters) == 0 {
		return nil, nil
	}

	ids := make([]uint64, 0, len(filters))

	err := e.WithTransaction(func() error {
		for _, filter := range filters {
			id, err := e.AddFilter(filter)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return ids, nil
}

// DeleteAllFilters removes all filters tracked by this engine.
func (e *Engine) DeleteAllFilters() error {
	e.mu.Lock()
	keys := e.filters.Values()
	e.mu.Unlock()

	if len(keys) == 0 {
		return nil
	}

	return e.WithTransaction(func() error {
		for _, key := range keys {
			if err := e.DeleteFilterByKey(key); err != nil {
				return err
			}
		}
		return nil
	})
}

// ============================================================================
// SafeOps Integration
// ============================================================================

// InitializeSafeOps registers the SafeOps provider and sublayer.
// Call this once after opening the engine.
func (e *Engine) InitializeSafeOps() error {
	// Register provider
	provider := NewSafeOpsProvider()
	if err := e.AddProvider(provider); err != nil {
		return fmt.Errorf("failed to register SafeOps provider: %w", err)
	}

	// Register sublayer
	sublayer := NewSafeOpsSublayer()
	if err := e.AddSublayer(sublayer); err != nil {
		return fmt.Errorf("failed to register SafeOps sublayer: %w", err)
	}

	return nil
}

// CleanupSafeOps removes SafeOps provider and sublayer (and all filters).
func (e *Engine) CleanupSafeOps() error {
	// Delete sublayer first (filters are in sublayer)
	if err := e.DeleteSublayer(SAFEOPS_SUBLAYER_GUID); err != nil {
		return fmt.Errorf("failed to delete SafeOps sublayer: %w", err)
	}

	// Delete provider
	if err := e.DeleteProvider(SAFEOPS_PROVIDER_GUID); err != nil {
		return fmt.Errorf("failed to delete SafeOps provider: %w", err)
	}

	return nil
}

// ============================================================================
// Statistics
// ============================================================================

// Stats returns engine statistics.
type Stats struct {
	IsOpen        bool
	InTransaction bool
	ProviderCount int
	SublayerCount int
	FilterCount   int
}

// GetStats returns current engine statistics.
func (e *Engine) GetStats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return Stats{
		IsOpen:        e.isOpen,
		InTransaction: e.inTxn,
		ProviderCount: e.providers.Size(),
		SublayerCount: e.sublayers.Size(),
		FilterCount:   e.filters.Size(),
	}
}

// ============================================================================
// Native Structure Builders
// ============================================================================
// These functions build Windows-native structures from Go structs.

// nativeFWPM_SESSION0 matches the Windows FWPM_SESSION0 layout.
type nativeFWPM_SESSION0 struct {
	SessionKey             GUID
	DisplayDataName        uintptr // *uint16
	DisplayDataDescription uintptr // *uint16
	Flags                  uint32
	TxnWaitTimeoutInMSec   uint32
	ProcessId              uint32
	Sid                    uintptr // *SID
	Username               uintptr // *uint16
	KernelMode             uint32
}

func (e *Engine) buildNativeSession(session *FWPM_SESSION0) (*nativeFWPM_SESSION0, []interface{}, error) {
	native := &nativeFWPM_SESSION0{
		SessionKey:           session.SessionKey,
		Flags:                uint32(session.Flags),
		TxnWaitTimeoutInMSec: session.TransactionWaitTimeoutMs,
	}

	var slices []interface{}

	// Convert display name
	if session.DisplayData.Name != "" {
		nameSlice, err := UTF8ToUTF16(session.DisplayData.Name)
		if err != nil {
			return nil, nil, err
		}
		native.DisplayDataName = uintptr(unsafe.Pointer(&nameSlice[0]))
		slices = append(slices, nameSlice)
	}

	// Convert description
	if session.DisplayData.Description != "" {
		descSlice, err := UTF8ToUTF16(session.DisplayData.Description)
		if err != nil {
			return nil, nil, err
		}
		native.DisplayDataDescription = uintptr(unsafe.Pointer(&descSlice[0]))
		slices = append(slices, descSlice)
	}

	return native, slices, nil
}

// nativeFWPM_PROVIDER0 matches the Windows FWPM_PROVIDER0 layout.
type nativeFWPM_PROVIDER0 struct {
	ProviderKey            GUID
	DisplayDataName        uintptr // *uint16
	DisplayDataDescription uintptr // *uint16
	Flags                  uint32
	ProviderData           uintptr // *FWP_BYTE_BLOB
	ServiceName            uintptr // *uint16
}

func (e *Engine) buildNativeProvider(provider *FWPM_PROVIDER0) (*nativeFWPM_PROVIDER0, []interface{}, error) {
	native := &nativeFWPM_PROVIDER0{
		ProviderKey: provider.ProviderKey,
		Flags:       uint32(provider.Flags),
	}

	var slices []interface{}

	if provider.DisplayData.Name != "" {
		nameSlice, err := UTF8ToUTF16(provider.DisplayData.Name)
		if err != nil {
			return nil, nil, err
		}
		native.DisplayDataName = uintptr(unsafe.Pointer(&nameSlice[0]))
		slices = append(slices, nameSlice)
	}

	if provider.DisplayData.Description != "" {
		descSlice, err := UTF8ToUTF16(provider.DisplayData.Description)
		if err != nil {
			return nil, nil, err
		}
		native.DisplayDataDescription = uintptr(unsafe.Pointer(&descSlice[0]))
		slices = append(slices, descSlice)
	}

	if provider.ServiceName != "" {
		svcSlice, err := UTF8ToUTF16(provider.ServiceName)
		if err != nil {
			return nil, nil, err
		}
		native.ServiceName = uintptr(unsafe.Pointer(&svcSlice[0]))
		slices = append(slices, svcSlice)
	}

	return native, slices, nil
}

// nativeFWPM_SUBLAYER0 matches the Windows FWPM_SUBLAYER0 layout.
type nativeFWPM_SUBLAYER0 struct {
	SublayerKey            GUID
	DisplayDataName        uintptr // *uint16
	DisplayDataDescription uintptr // *uint16
	Flags                  uint16
	_                      [2]byte // padding
	ProviderKey            uintptr // *GUID
	ProviderData           uintptr // *FWP_BYTE_BLOB
	Weight                 uint16
	_                      [2]byte // padding
}

func (e *Engine) buildNativeSublayer(sublayer *FWPM_SUBLAYER0) (*nativeFWPM_SUBLAYER0, []interface{}, error) {
	native := &nativeFWPM_SUBLAYER0{
		SublayerKey: sublayer.SublayerKey,
		Flags:       sublayer.Flags,
		Weight:      sublayer.Weight,
	}

	var slices []interface{}

	if sublayer.DisplayData.Name != "" {
		nameSlice, err := UTF8ToUTF16(sublayer.DisplayData.Name)
		if err != nil {
			return nil, nil, err
		}
		native.DisplayDataName = uintptr(unsafe.Pointer(&nameSlice[0]))
		slices = append(slices, nameSlice)
	}

	if sublayer.DisplayData.Description != "" {
		descSlice, err := UTF8ToUTF16(sublayer.DisplayData.Description)
		if err != nil {
			return nil, nil, err
		}
		native.DisplayDataDescription = uintptr(unsafe.Pointer(&descSlice[0]))
		slices = append(slices, descSlice)
	}

	if sublayer.ProviderKey != nil {
		native.ProviderKey = uintptr(unsafe.Pointer(sublayer.ProviderKey))
		slices = append(slices, sublayer.ProviderKey)
	}

	return native, slices, nil
}

// nativeFWPM_FILTER0 matches the Windows FWPM_FILTER0 layout (simplified).
type nativeFWPM_FILTER0 struct {
	FilterKey              GUID
	DisplayDataName        uintptr // *uint16
	DisplayDataDescription uintptr // *uint16
	Flags                  uint32
	ProviderKey            uintptr // *GUID
	ProviderData           uintptr // *FWP_BYTE_BLOB
	LayerKey               GUID
	SublayerKey            GUID
	Weight                 nativeFWP_VALUE0
	NumFilterConditions    uint32
	FilterConditions       uintptr // *FWPM_FILTER_CONDITION0
	Action                 nativeFWPM_ACTION0
	// More fields exist but we don't need them for basic filtering
}

type nativeFWP_VALUE0 struct {
	Type  uint32
	_     [4]byte // padding for alignment
	Value uint64  // Union - fits largest member
}

type nativeFWPM_ACTION0 struct {
	Type uint32
	GUID GUID // callout GUID (unused for BLOCK/PERMIT)
}

func (e *Engine) buildNativeFilter(filter *FWPM_FILTER0) (*nativeFWPM_FILTER0, []interface{}, error) {
	native := &nativeFWPM_FILTER0{
		FilterKey:   filter.FilterKey,
		Flags:       uint32(filter.Flags),
		LayerKey:    filter.LayerKey,
		SublayerKey: filter.SublayerKey,
		Action:      nativeFWPM_ACTION0{Type: uint32(filter.Action.Type)},
	}

	var slices []interface{}

	// Display data
	if filter.DisplayData.Name != "" {
		nameSlice, err := UTF8ToUTF16(filter.DisplayData.Name)
		if err != nil {
			return nil, nil, err
		}
		native.DisplayDataName = uintptr(unsafe.Pointer(&nameSlice[0]))
		slices = append(slices, nameSlice)
	}

	if filter.DisplayData.Description != "" {
		descSlice, err := UTF8ToUTF16(filter.DisplayData.Description)
		if err != nil {
			return nil, nil, err
		}
		native.DisplayDataDescription = uintptr(unsafe.Pointer(&descSlice[0]))
		slices = append(slices, descSlice)
	}

	// Provider key
	if filter.ProviderKey != nil {
		native.ProviderKey = uintptr(unsafe.Pointer(filter.ProviderKey))
		slices = append(slices, filter.ProviderKey)
	}

	// Weight
	native.Weight = nativeFWP_VALUE0{
		Type:  uint32(FWP_UINT8),
		Value: filter.Weight.Value,
	}
	if filter.Weight.Type == 2 {
		native.Weight.Type = uint32(FWP_UINT64)
	}

	// Conditions would be built here, but this is complex
	// For now, we support filters without conditions (match all)
	// Full condition support requires building native condition arrays
	native.NumFilterConditions = 0
	native.FilterConditions = 0

	return native, slices, nil
}
