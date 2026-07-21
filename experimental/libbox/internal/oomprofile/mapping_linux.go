//go:build linux

package oomprofile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func (b *profileBuilder) readMapping() {
	data, _ := os.ReadFile("/proc/self/maps")
	parseProcSelfMaps(data, b.addMapping)
	if len(b.mem) == 0 {
		b.addMappingEntry(0, 0, 0, "", "", true)
	}
}

// parseProcSelfMaps is vendored from runtime/pprof.parseProcSelfMaps (Go 1.25.6,
// src/runtime/pprof/proto.go) - that function has no go:linkname push marker in this Go
// version, so pulling it via go:linkname fails at link time. Only elfBuildID (still
// linknamed, see linkname.go) is reused as-is; this parses /proc/self/maps' well-known
// format directly instead.
func parseProcSelfMaps(data []byte, addMapping func(lo, hi, offset uint64, file, buildID string)) {
	var space = []byte(" ")
	var newline = []byte("\n")

	var line []byte
	next := func() []byte {
		var f []byte
		f, line, _ = bytes.Cut(line, space)
		line = bytes.TrimLeft(line, " ")
		return f
	}

	for len(data) > 0 {
		line, data, _ = bytes.Cut(data, newline)
		addr := next()
		loStr, hiStr, ok := strings.Cut(string(addr), "-")
		if !ok {
			continue
		}
		lo, err := strconv.ParseUint(loStr, 16, 64)
		if err != nil {
			continue
		}
		hi, err := strconv.ParseUint(hiStr, 16, 64)
		if err != nil {
			continue
		}
		perm := next()
		if len(perm) < 4 || perm[2] != 'x' {
			// Only interested in executable mappings.
			continue
		}
		offset, err := strconv.ParseUint(string(next()), 16, 64)
		if err != nil {
			continue
		}
		next()          // dev
		inode := next() // inode
		if line == nil {
			continue
		}
		file := string(line)

		// Trim deleted file marker.
		const deletedStr = " (deleted)"
		if len(file) >= len(deletedStr) && file[len(file)-len(deletedStr):] == deletedStr {
			file = file[:len(file)-len(deletedStr)]
		}

		if len(inode) == 1 && inode[0] == '0' && file == "" {
			// Huge-page text mappings list the initial fragment of
			// mapped but unpopulated memory as being inode 0.
			// Don't report that part.
			// But [vdso] and [vsyscall] are inode 0, so let non-empty file names through.
			continue
		}

		buildID, _ := elfBuildID(file)
		addMapping(lo, hi, offset, file, buildID)
	}
}

var (
	errBadELF    = errors.New("malformed ELF binary")
	errNoBuildID = errors.New("no NT_GNU_BUILD_ID found in ELF binary")
)

// elfBuildID is vendored from runtime/pprof.elfBuildID (Go 1.25.6, src/runtime/pprof/elf.go) -
// see the comment in linkname.go for why this isn't pulled via go:linkname instead.
func elfBuildID(file string) (string, error) {
	buf := make([]byte, 256)
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := f.ReadAt(buf[:64], 0); err != nil {
		return "", err
	}

	// ELF file begins with \x7F E L F.
	if buf[0] != 0x7F || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F' {
		return "", errBadELF
	}

	var byteOrder binary.ByteOrder
	switch buf[5] {
	default:
		return "", errBadELF
	case 1: // little-endian
		byteOrder = binary.LittleEndian
	case 2: // big-endian
		byteOrder = binary.BigEndian
	}

	var shnum int
	var shoff, shentsize int64
	switch buf[4] {
	default:
		return "", errBadELF
	case 1: // 32-bit file header
		shoff = int64(byteOrder.Uint32(buf[32:]))
		shentsize = int64(byteOrder.Uint16(buf[46:]))
		if shentsize != 40 {
			return "", errBadELF
		}
		shnum = int(byteOrder.Uint16(buf[48:]))
	case 2: // 64-bit file header
		shoff = int64(byteOrder.Uint64(buf[40:]))
		shentsize = int64(byteOrder.Uint16(buf[58:]))
		if shentsize != 64 {
			return "", errBadELF
		}
		shnum = int(byteOrder.Uint16(buf[60:]))
	}

	for i := 0; i < shnum; i++ {
		if _, err := f.ReadAt(buf[:shentsize], shoff+int64(i)*shentsize); err != nil {
			return "", err
		}
		if typ := byteOrder.Uint32(buf[4:]); typ != 7 { // SHT_NOTE
			continue
		}
		var off, size int64
		if shentsize == 40 {
			// 32-bit section header
			off = int64(byteOrder.Uint32(buf[16:]))
			size = int64(byteOrder.Uint32(buf[20:]))
		} else {
			// 64-bit section header
			off = int64(byteOrder.Uint64(buf[24:]))
			size = int64(byteOrder.Uint64(buf[32:]))
		}
		size += off
		for off < size {
			if _, err := f.ReadAt(buf[:16], off); err != nil { // room for header + name GNU\x00
				return "", err
			}
			nameSize := int(byteOrder.Uint32(buf[0:]))
			descSize := int(byteOrder.Uint32(buf[4:]))
			noteType := int(byteOrder.Uint32(buf[8:]))
			descOff := off + int64(12+(nameSize+3)&^3)
			off = descOff + int64((descSize+3)&^3)
			if nameSize != 4 || noteType != 3 || buf[12] != 'G' || buf[13] != 'N' || buf[14] != 'U' || buf[15] != '\x00' { // want name GNU\x00 type 3 (NT_GNU_BUILD_ID)
				continue
			}
			if descSize > len(buf) {
				return "", errBadELF
			}
			if _, err := f.ReadAt(buf[:descSize], descOff); err != nil {
				return "", err
			}
			return fmt.Sprintf("%x", buf[:descSize]), nil
		}
	}
	return "", errNoBuildID
}
