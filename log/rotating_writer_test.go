package log

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestRotatingFileWriterRotatesPastCap is the regression guard for "debug logging grows the log
// file unbounded" (previously os.O_APPEND with no size check at all - see maxLogFileSize's doc
// comment). It writes past maxLogFileSize in one call and checks that a ".1" backup was created,
// the live file was reset rather than left to keep growing, and no bytes were silently dropped.
func TestRotatingFileWriterRotatesPastCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := newRotatingFileWriter(context.Background(), path)
	if err != nil {
		t.Fatalf("newRotatingFileWriter: %v", err)
	}
	defer w.Close()

	small := []byte("first line\n")
	if _, err := w.Write(small); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("expected no backup file yet after a small write, stat err: %v", err)
	}

	overflow := bytes.Repeat([]byte("x"), maxLogFileSize+1)
	if _, err := w.Write(overflow); err != nil {
		t.Fatalf("write overflow: %v", err)
	}

	backupInfo, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatalf("expected a backup file after exceeding maxLogFileSize, stat err: %v", err)
	}
	if backupInfo.Size() != int64(len(small)) {
		t.Fatalf("expected the backup to hold the pre-rotation content (%d bytes), got %d", len(small), backupInfo.Size())
	}

	liveInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat live file: %v", err)
	}
	if liveInfo.Size() != int64(len(overflow)) {
		t.Fatalf("expected the live file to hold exactly the post-rotation write (%d bytes), got %d", len(overflow), liveInfo.Size())
	}
	if w.size != liveInfo.Size() {
		t.Fatalf("writer's internal size tracker (%d) drifted from the actual file size (%d)", w.size, liveInfo.Size())
	}
}

// TestRotatingFileWriterAccumulatesBelowCap guards against rotating on every write once close to
// the cap - only a write that would actually push the file over maxLogFileSize should rotate.
func TestRotatingFileWriterAccumulatesBelowCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := newRotatingFileWriter(context.Background(), path)
	if err != nil {
		t.Fatalf("newRotatingFileWriter: %v", err)
	}
	defer w.Close()

	chunk := bytes.Repeat([]byte("y"), 1024)
	for i := 0; i < 10; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("did not expect a backup file while total writes stay well under maxLogFileSize")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != int64(10*len(chunk)) {
		t.Fatalf("expected %d bytes accumulated in the live file, got %d", 10*len(chunk), info.Size())
	}
}
