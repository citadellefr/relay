package main

import (
	"io"
	"net"
)

// frameSize caps what one write puts in the tunnel's send queue. Frames leave
// in the order they were queued, one per busy stream: at 32 KiB, a few uploads
// on a slow link held a call's signalling seconds behind them, where 4 KiB
// frames let it through between theirs.
const frameSize = 4096

func writeFrames(w io.Writer, p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n, err := w.Write(p[:min(len(p), frameSize)])
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// framedStream writes into the tunnel in frames of at most frameSize.
type framedStream struct{ net.Conn }

func (s framedStream) Write(p []byte) (int, error) { return writeFrames(s.Conn, p) }
