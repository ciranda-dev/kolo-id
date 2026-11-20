// syscall.Mkfifo does not exist on aix, solaris and illumos.

//go:build unix && !aix && !solaris

package koloid

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func loadWithin(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := Load(path)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("Load(%s) did not return", path)
		return nil
	}
}

// blockedWriter starts a goroutine that opens fifo for writing, which blocks until a reader opens it,
// and returns once that goroutine is about to make the call. The channel yields the writer when the open returns.
func blockedWriter(t *testing.T, fifo string) chan *os.File {
	t.Helper()
	opened := make(chan *os.File, 1)
	ready := make(chan struct{})
	go func() {
		close(ready)
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
		}
		opened <- w
	}()
	<-ready
	runtime.Gosched()
	t.Cleanup(func() {
		r, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if w := <-opened; w != nil {
			w.Close()
		}
		r.Close()
	})
	return opened
}

// Proves the Lstat filter: a blocked writer's open returns only if Load opens the read end.
func TestLoadNeverOpensFIFO(t *testing.T) {
	path := filepath.Join(keyDir(t), "id.key")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	opened := blockedWriter(t, path)
	if err := loadWithin(t, path); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("Load of a FIFO returned %v, want %v", err, ErrInvalidKeyFile)
	}
	select {
	case w := <-opened:
		opened <- w
		t.Fatal("Load opened the FIFO: the blocked writer's open returned")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestLoadRejectsFIFO(t *testing.T) {
	path := filepath.Join(keyDir(t), "id.key")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	if err := loadWithin(t, path); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("Load of a FIFO returned %v, want %v", err, ErrInvalidKeyFile)
	}
}

// Lstat rejects the symlink, so /dev/zero is never opened. Load runs in a
// child process so a regression that follows the symlink and reads it is killed, not left running.
func TestLoadRejectsDevZero(t *testing.T) {
	if dir := os.Getenv("KOLOID_DEVZERO_DIR"); dir != "" {
		loadDevZeroChild(t, dir)
		return
	}
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoadRejectsDevZero$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KOLOID_DEVZERO_DIR="+keyDir(t))
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("Load on a symlink to /dev/zero did not return within 5s; the child was killed\n%s", out)
	}
	if err != nil {
		t.Fatalf("Load on a symlink to /dev/zero failed in the child: %v\n%s", err, out)
	}
}

const devZeroHeapLimit = 64 << 20

func loadDevZeroChild(t *testing.T, dir string) {
	path := filepath.Join(dir, "id.key")
	if err := os.Symlink("/dev/zero", path); err != nil {
		t.Fatal(err)
	}
	go func() {
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > devZeroHeapLimit {
				fmt.Fprintf(os.Stderr, "Load is reading /dev/zero: heap passed %d MiB\n", devZeroHeapLimit>>20)
				os.Exit(3)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	if _, err := Load(path); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("Load of /dev/zero returned %v, want %v", err, ErrInvalidKeyFile)
	}
}
