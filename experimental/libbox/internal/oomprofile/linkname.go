//go:build darwin || linux || windows

package oomprofile

import (
	"runtime"
	_ "runtime/pprof"
	"unsafe"
	_ "unsafe"
)

//go:linkname runtimeMemProfileInternal runtime.pprof_memProfileInternal
func runtimeMemProfileInternal(p []memProfileRecord, inuseZero bool) (n int, ok bool)

//go:linkname runtimeBlockProfileInternal runtime.pprof_blockProfileInternal
func runtimeBlockProfileInternal(p []blockProfileRecord) (n int, ok bool)

//go:linkname runtimeMutexProfileInternal runtime.pprof_mutexProfileInternal
func runtimeMutexProfileInternal(p []blockProfileRecord) (n int, ok bool)

//go:linkname runtimeThreadCreateInternal runtime.pprof_threadCreateInternal
func runtimeThreadCreateInternal(p []stackRecord) (n int, ok bool)

//go:linkname runtimeGoroutineProfileWithLabels runtime.pprof_goroutineProfileWithLabels
func runtimeGoroutineProfileWithLabels(p []stackRecord, labels []unsafe.Pointer) (n int, ok bool)

//go:linkname runtimeCyclesPerSecond runtime/pprof.runtime_cyclesPerSecond
func runtimeCyclesPerSecond() int64

//go:linkname runtimeMakeProfStack runtime.pprof_makeProfStack
func runtimeMakeProfStack() []uintptr

//go:linkname runtimeFrameStartLine runtime/pprof.runtime_FrameStartLine
func runtimeFrameStartLine(f *runtime.Frame) int

//go:linkname runtimeFrameSymbolName runtime/pprof.runtime_FrameSymbolName
func runtimeFrameSymbolName(f *runtime.Frame) string

//go:linkname runtimeExpandFinalInlineFrame runtime/pprof.runtime_expandFinalInlineFrame
func runtimeExpandFinalInlineFrame(stk []uintptr) []uintptr

// Neither runtime/pprof.parseProcSelfMaps nor runtime/pprof.elfBuildID has a matching
// go:linkname push marker in this Go version's runtime/pprof, so pulling them (as this file
// used to, via stdParseProcSelfMaps/stdELFBuildID declarations) fails at link time
// ("invalid reference to runtime/pprof.parseProcSelfMaps" / "...elfBuildID"). Both are small,
// self-contained (ELF-note parsing / /proc/self/maps parsing), so mapping_linux.go vendors
// them locally (as parseProcSelfMaps and elfBuildID) instead of linknaming them.
