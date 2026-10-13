package sip

import "bytes"

// Malformed reports whether one SIP datagram or WebSocket frame is certain
// to be rejected by sipgo's message parser (Parser.ParseSIP, v1.4.3). It is
// the cheap pre-validation the edge's read filter runs on public reads to
// feed the shield's offender table (issue #190), where sipgo itself only
// logs the failure with no notion of the source.
//
// It is a deliberately strict subset of what the parser rejects: a false
// result says nothing, a true result must never be wrong, so a valid message
// is never struck. Only three structural faults are checked, none of which
// allocates:
//
//   - the start line is not a request line or a status line (what sipgo's
//     parseLine decides), or is not CRLF-terminated;
//   - the header section is never closed by an empty line (no CRLFCRLF
//     anywhere), so the parser runs out of data;
//   - a header, with its folded continuation lines, has no colon.
//
// A keep-alive (CRLF or CRLFCRLF) and a read of only NUL, CR and LF bytes
// are not flagged: sipgo discards them before parsing. Header values are
// never inspected, so a Via or CSeq the parser dislikes is not flagged.
// TestSipgoMalformedScanContract and FuzzMalformedScan, in the edge package,
// fail if a sipgo upgrade breaks the subset.
func Malformed(data []byte) bool {
	ignorable := true
	for _, c := range data {
		if c != 0 && c != '\r' && c != '\n' {
			ignorable = false
			break
		}
	}
	if ignorable {
		return false
	}
	// Start line: terminated by CRLF (a bare CR is a parse error, so is a
	// missing terminator).
	i := bytes.IndexByte(data, '\r')
	if i < 0 || i+1 >= len(data) || data[i+1] != '\n' {
		return true
	}
	if !requestOrStatusLine(data[:i]) {
		return true
	}
	// The header section ends at the first empty line.
	if !bytes.Contains(data[i:], []byte("\r\n\r\n")) {
		return true
	}
	rest := data[i+2:]
	// A header is its first line plus the continuation lines (space or tab
	// first) that follow, which sipgo folds into one before looking for the
	// colon, so the colon may sit on any of them. Only the line right after
	// the start line is always a header's first line.
	first, colon := true, true
	for len(rest) > 0 {
		j := bytes.Index(rest, []byte("\r\n"))
		if j < 0 {
			break // unreachable once CRLFCRLF was found; stay safe
		}
		line := rest[:j]
		rest = rest[j+2:]
		if !first && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			colon = colon || bytes.IndexByte(line, ':') >= 0
			continue
		}
		if !colon {
			return true // the header just ended never had a colon
		}
		if len(line) == 0 {
			break // end of headers
		}
		first = false
		colon = bytes.IndexByte(line, ':') >= 0
	}
	return false
}

// requestOrStatusLine mirrors sipgo's split3, isRequest and isResponse: two
// spaces split the line in three, and it is a request when the third part
// has no space and starts with "SIP" and a response when the first part
// starts with "SIP" (either case, three bytes). Anything else is "not a SIP
// message" to the parser.
func requestOrStatusLine(line []byte) bool {
	i := bytes.IndexByte(line, ' ')
	if i < 0 {
		return false
	}
	p0, rest := line[:i], line[i+1:]
	k := bytes.IndexByte(rest, ' ')
	if k < 0 {
		return false
	}
	p2 := rest[k+1:]
	if len(p2) >= 3 && bytes.IndexByte(p2, ' ') < 0 && isSIP(p2[:3]) {
		return true
	}
	return len(p0) >= 3 && isSIP(p0[:3])
}

func isSIP(b []byte) bool {
	return string(b) == "SIP" || string(b) == "sip"
}
