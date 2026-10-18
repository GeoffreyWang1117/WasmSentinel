package collector

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func quietLogger() *logrus.Logger {
	lg := logrus.New()
	lg.SetOutput(io.Discard)
	return lg
}

func writeTrace(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadTraceSkipsGarbage(t *testing.T) {
	p := writeTrace(t, t.TempDir(), "a.txt", "5 6 6 x 125\n5 33\n")
	got, err := LoadTrace(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 || got[2] != 6 || got[5] != 33 {
		t.Errorf("parsed %v", got)
	}
}

func TestReplayEmitsEveryEventThenCloses(t *testing.T) {
	dir := t.TempDir()
	writeTrace(t, dir, "b.txt", "1 2 3")
	writeTrace(t, dir, "a.txt", "7 8")
	c, err := NewReplayCollector(quietLogger(), ReplayConfig{Path: dir, Binary: true})
	if err != nil {
		t.Fatal(err)
	}
	if n, total := c.Traces(); n != 2 || total != 5 {
		t.Fatalf("loaded %d traces / %d events", n, total)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []uint32
	var pids []uint32
	for ev := range c.EventChannel() {
		if ev.Type != "syscall" || ev.Source != "replay" || ev.Binary == nil {
			t.Fatalf("bad event %+v", ev)
		}
		got = append(got, ev.Data["syscall_nr"].(uint32))
		pids = append(pids, ev.Data["pid"].(uint32))
	}
	// sorted order: a.txt then b.txt; one pid per trace
	want := []uint32{7, 8, 1, 2, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
	if pids[0] != pids[1] || pids[1] == pids[2] {
		t.Errorf("pids %v", pids)
	}
	if c.Emitted() != 5 {
		t.Errorf("emitted %d", c.Emitted())
	}
	_ = c.Stop()
	_ = c.Stop()
}

func TestReplayPacingAndStop(t *testing.T) {
	dir := t.TempDir()
	writeTrace(t, dir, "t.txt", "1 2 3 4 5 6 7 8 9 10")
	c, err := NewReplayCollector(quietLogger(), ReplayConfig{Path: dir, EventsPerSecond: 200, Loop: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ { // looping: more events than the trace holds
		if _, ok := <-c.EventChannel(); !ok {
			t.Fatal("channel closed while looping")
		}
	}
	if el := time.Since(start); el < 60*time.Millisecond {
		t.Errorf("20 events at 200 eps took only %s", el)
	}
	_ = c.Stop()
	if _, ok := <-c.EventChannel(); ok {
		// drain whatever was buffered; the channel must eventually close
		for range c.EventChannel() {
		}
	}
}

func TestReplayRejectsMissingPath(t *testing.T) {
	if _, err := NewReplayCollector(quietLogger(), ReplayConfig{Path: "/nonexistent/trace.txt"}); err == nil {
		t.Error("missing path accepted")
	}
}
