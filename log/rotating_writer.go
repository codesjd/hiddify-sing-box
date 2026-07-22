package log

import (
	"context"
	"os"
	"sync"

	"github.com/sagernet/sing/service/filemanager"
)

// maxLogFileSize caps how large the box's own log file (data/box.log) is allowed to grow before
// it's rotated. Debug level logs at connection/query granularity (see route/route.go's per-request
// rule-match and sniff logging, dns/router.go's per-query logging, etc.) and, prior to this cap,
// nothing ever truncated or rotated the file at all (os.O_APPEND|os.O_CREATE|os.O_WRONLY, opened
// once and written to for the entire process lifetime) - over a real debug-enabled session this
// grew unbounded, reported as ~13-15GB, which made the file too large to actually collect and
// share for diagnosing an unrelated connectivity bug. A single rotation with one backup bounds the
// worst case to roughly 2x this size regardless of session length or logging volume.
const maxLogFileSize = 20 * 1024 * 1024

// rotatingFileWriter wraps the box's log file with a single size-triggered rotation: once the
// current file would exceed maxLogFileSize, it's renamed to a ".1" backup and a fresh file is
// started. This intentionally does not try to be a general-purpose log-rotation library (no
// time-based rotation, no compression, no configurable backup count) - the only goal is putting a
// hard ceiling on how large a single debug session's log output can get.
type rotatingFileWriter struct {
	mu   sync.Mutex
	ctx  context.Context
	path string
	file *os.File
	size int64
}

func newRotatingFileWriter(ctx context.Context, path string) (*rotatingFileWriter, error) {
	file, err := filemanager.OpenFile(ctx, path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &rotatingFileWriter{ctx: ctx, path: path, file: file, size: info.Size()}, nil
}

func (w *rotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size > 0 && w.size+int64(len(p)) > maxLogFileSize {
		w.rotateLocked()
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// rotateLocked best-efforts the rotation: if renaming or reopening fails (e.g. the backup path is
// locked by another process reading it), it leaves the existing file handle in place so logging
// keeps working rather than erroring out - a failed rotation just means this cycle grows past the
// cap, not that logging stops.
func (w *rotatingFileWriter) rotateLocked() {
	if err := w.file.Close(); err != nil {
		return
	}
	backupPath := w.path + ".1"
	os.Remove(backupPath)
	os.Rename(w.path, backupPath)
	file, err := filemanager.OpenFile(w.ctx, w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		// Reopening failed - fall back to reopening the original path in append mode so at least
		// something keeps accepting writes.
		file, err = filemanager.OpenFile(w.ctx, w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
	}
	w.file = file
	w.size = 0
}

func (w *rotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}
