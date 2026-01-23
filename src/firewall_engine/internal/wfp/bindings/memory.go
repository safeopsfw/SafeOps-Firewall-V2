// Package bindings provides low-level Go bindings to Windows Filtering Platform (WFP) APIs.
package bindings

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// ============================================================================
// Memory Management
// ============================================================================
// When crossing the Go-C boundary, memory ownership must be carefully managed:
// - Go allocates: Go's GC will free when no longer referenced
// - Windows allocates: Must call CoTaskMemFree or HeapFree
// - Shared: Use runtime.KeepAlive to prevent premature GC

var (
	// Windows DLLs for memory operations
	ole32DLL    = syscall.NewLazyDLL("ole32.dll")
	kernel32DLL = syscall.NewLazyDLL("kernel32.dll")

	// Memory allocation procedures
	procCoTaskMemAlloc = ole32DLL.NewProc("CoTaskMemAlloc")
	procCoTaskMemFree  = ole32DLL.NewProc("CoTaskMemFree")
	procHeapAlloc      = kernel32DLL.NewProc("HeapAlloc")
	procHeapFree       = kernel32DLL.NewProc("HeapFree")
	procGetProcessHeap = kernel32DLL.NewProc("GetProcessHeap")

	// Process heap handle (cached)
	processHeap     uintptr
	processHeapOnce sync.Once
)

// getProcessHeap returns the process heap handle (lazily initialized).
func getProcessHeap() uintptr {
	processHeapOnce.Do(func() {
		heap, _, _ := procGetProcessHeap.Call()
		processHeap = heap
	})
	return processHeap
}

// ============================================================================
// CoTaskMem Allocation (COM memory)
// ============================================================================
// CoTaskMem is used by COM and many Windows APIs including WFP.

// CoTaskMemAlloc allocates memory from the COM task allocator.
// Returns nil if allocation fails.
// IMPORTANT: Caller must call CoTaskMemFree when done.
func CoTaskMemAlloc(size uintptr) unsafe.Pointer {
	ptr, _, _ := procCoTaskMemAlloc.Call(size)
	if ptr == 0 {
		return nil
	}
	return unsafe.Pointer(ptr)
}

// CoTaskMemFree frees memory allocated by CoTaskMemAlloc.
// Safe to call with nil pointer.
func CoTaskMemFree(ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}
	procCoTaskMemFree.Call(uintptr(ptr))
}

// ============================================================================
// Heap Allocation (Windows heap memory)
// ============================================================================

const (
	HEAP_ZERO_MEMORY = 0x00000008
)

// HeapAlloc allocates memory from the process heap.
// Returns nil if allocation fails.
// IMPORTANT: Caller must call HeapFree when done.
func HeapAlloc(size uintptr, zeroMemory bool) unsafe.Pointer {
	flags := uintptr(0)
	if zeroMemory {
		flags = HEAP_ZERO_MEMORY
	}

	ptr, _, _ := procHeapAlloc.Call(
		getProcessHeap(),
		flags,
		size,
	)
	if ptr == 0 {
		return nil
	}
	return unsafe.Pointer(ptr)
}

// HeapFree frees memory allocated by HeapAlloc.
// Safe to call with nil pointer.
func HeapFree(ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}
	procHeapFree.Call(
		getProcessHeap(),
		0,
		uintptr(ptr),
	)
}

// ============================================================================
// Go Memory Helpers
// ============================================================================

// AllocBytes allocates a byte slice of the given size.
// Returns the slice and an unsafe.Pointer to the first element.
// The slice must be kept alive (referenced) until the pointer is no longer used.
func AllocBytes(size int) ([]byte, unsafe.Pointer) {
	if size <= 0 {
		return nil, nil
	}

	slice := make([]byte, size)
	return slice, unsafe.Pointer(&slice[0])
}

// BytesToPointer returns an unsafe.Pointer to the first element of a byte slice.
// Returns nil if slice is empty.
func BytesToPointer(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}

// PointerToBytes creates a byte slice from an unsafe.Pointer and length.
// Does NOT copy the data - slice shares memory with the pointer.
// DANGEROUS: Ensure pointer remains valid for lifetime of the slice.
func PointerToBytes(ptr unsafe.Pointer, length int) []byte {
	if ptr == nil || length <= 0 {
		return nil
	}
	return unsafe.Slice((*byte)(ptr), length)
}

// CopyFromPointer copies data from an unsafe.Pointer to a new byte slice.
// Safe to use as it creates a copy.
func CopyFromPointer(ptr unsafe.Pointer, length int) []byte {
	if ptr == nil || length <= 0 {
		return nil
	}

	result := make([]byte, length)
	copy(result, unsafe.Slice((*byte)(ptr), length))
	return result
}

// ============================================================================
// Struct Allocation
// ============================================================================

// AllocStruct allocates a zeroed struct of the given size.
// Returns pointer to the allocated memory.
// Caller must call FreeStruct when done.
func AllocStruct(size uintptr) unsafe.Pointer {
	return HeapAlloc(size, true)
}

// FreeStruct frees memory allocated by AllocStruct.
func FreeStruct(ptr unsafe.Pointer) {
	HeapFree(ptr)
}

// ============================================================================
// KeepAlive Helpers
// ============================================================================
// runtime.KeepAlive prevents garbage collection of objects that may have
// pointers passed to Windows APIs. Call at the end of the API operation.

// KeepAlive is an alias for runtime.KeepAlive.
// Use to prevent GC of objects with pointers passed to Windows APIs.
func KeepAlive(x interface{}) {
	runtime.KeepAlive(x)
}

// KeepAliveMany keeps multiple objects alive.
func KeepAliveMany(objects ...interface{}) {
	for _, obj := range objects {
		runtime.KeepAlive(obj)
	}
}

// ============================================================================
// Memory Pool (for frequent allocations)
// ============================================================================

// BytePool is a sync.Pool for byte slices of common sizes.
type BytePool struct {
	pools []*sync.Pool
	sizes []int
}

// NewBytePool creates a new byte pool with the given sizes.
func NewBytePool(sizes ...int) *BytePool {
	bp := &BytePool{
		pools: make([]*sync.Pool, len(sizes)),
		sizes: sizes,
	}

	for i, size := range sizes {
		s := size // Capture for closure
		bp.pools[i] = &sync.Pool{
			New: func() interface{} {
				return make([]byte, s)
			},
		}
	}

	return bp
}

// Get returns a byte slice of at least the requested size.
// Returns nil if no suitable pool exists.
func (bp *BytePool) Get(minSize int) []byte {
	for i, size := range bp.sizes {
		if size >= minSize {
			return bp.pools[i].Get().([]byte)
		}
	}
	// No suitable pool, allocate directly
	return make([]byte, minSize)
}

// Put returns a byte slice to the pool.
// Slice is zeroed before returning to pool for security.
func (bp *BytePool) Put(b []byte) {
	// Find matching pool
	for i, size := range bp.sizes {
		if len(b) == size {
			// Zero the slice for security
			for j := range b {
				b[j] = 0
			}
			bp.pools[i].Put(b)
			return
		}
	}
	// No matching pool, let GC handle it
}

// ============================================================================
// Default Pools
// ============================================================================

var (
	// defaultBytePool contains common allocation sizes for WFP operations.
	defaultBytePool = NewBytePool(64, 256, 1024, 4096)
)

// GetBytes returns a byte slice from the default pool.
func GetBytes(minSize int) []byte {
	return defaultBytePool.Get(minSize)
}

// PutBytes returns a byte slice to the default pool.
func PutBytes(b []byte) {
	defaultBytePool.Put(b)
}

// ============================================================================
// Alignment Helpers
// ============================================================================

// Align returns the smallest multiple of alignment >= n.
func Align(n, alignment uintptr) uintptr {
	return (n + alignment - 1) &^ (alignment - 1)
}

// Align8 aligns n to 8 bytes (x64 pointer alignment).
func Align8(n uintptr) uintptr {
	return Align(n, 8)
}

// Align4 aligns n to 4 bytes (x86/64 DWORD alignment).
func Align4(n uintptr) uintptr {
	return Align(n, 4)
}

// ============================================================================
// Memory Arena (for batch allocations)
// ============================================================================

// Arena is a simple memory arena for batch allocations.
// All allocations are freed together when Reset or Free is called.
// Useful for building WFP filter conditions.
type Arena struct {
	chunks [][]byte
	offset int
}

// NewArena creates a new arena with the given initial capacity.
func NewArena(initialCapacity int) *Arena {
	return &Arena{
		chunks: [][]byte{make([]byte, initialCapacity)},
		offset: 0,
	}
}

// Alloc allocates n bytes from the arena.
// Returns a pointer to the allocated memory.
func (a *Arena) Alloc(n int) unsafe.Pointer {
	n = int(Align8(uintptr(n))) // Align to 8 bytes

	// Check if current chunk has space
	currentChunk := a.chunks[len(a.chunks)-1]
	if a.offset+n > len(currentChunk) {
		// Need new chunk
		newSize := len(currentChunk) * 2
		if newSize < n {
			newSize = n * 2
		}
		a.chunks = append(a.chunks, make([]byte, newSize))
		a.offset = 0
		currentChunk = a.chunks[len(a.chunks)-1]
	}

	ptr := unsafe.Pointer(&currentChunk[a.offset])
	a.offset += n
	return ptr
}

// AllocSlice allocates a byte slice of n bytes from the arena.
func (a *Arena) AllocSlice(n int) []byte {
	ptr := a.Alloc(n)
	return unsafe.Slice((*byte)(ptr), n)
}

// Reset resets the arena, allowing memory to be reused.
// Previous allocations become invalid.
func (a *Arena) Reset() {
	a.chunks = a.chunks[:1] // Keep first chunk
	a.offset = 0
}

// Free releases all arena memory.
// After calling Free, the arena should not be used.
func (a *Arena) Free() {
	a.chunks = nil
	a.offset = 0
}

// Size returns the total allocated size.
func (a *Arena) Size() int {
	total := 0
	for _, chunk := range a.chunks {
		total += len(chunk)
	}
	return total
}
