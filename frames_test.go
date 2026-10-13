package main

import (
	"bytes"
	"errors"
	"testing"
)

type recordingWriter struct {
	writes [][]byte
	failAt int
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	if w.failAt > 0 && len(w.writes) == w.failAt {
		return 10, errors.New("closed")
	}
	w.writes = append(w.writes, bytes.Clone(p))
	return len(p), nil
}

func TestWriteFrames(t *testing.T) {
	p := bytes.Repeat([]byte("0123456789abcdef"), 2500) // 40000 bytes
	w := &recordingWriter{}
	n, err := writeFrames(w, p)
	if err != nil || n != len(p) {
		t.Fatalf("wrote %d, %v", n, err)
	}
	if len(w.writes) != 10 {
		t.Errorf("%d frames, want 10", len(w.writes))
	}
	for _, f := range w.writes {
		if len(f) > frameSize {
			t.Fatalf("frame of %d bytes", len(f))
		}
	}
	if !bytes.Equal(bytes.Join(w.writes, nil), p) {
		t.Error("frames do not add up to the input")
	}

	w = &recordingWriter{failAt: 2}
	n, err = writeFrames(w, p)
	if err == nil || n != 2*frameSize+10 {
		t.Errorf("after a failed frame: %d, %v; want %d and the error", n, err, 2*frameSize+10)
	}
}
