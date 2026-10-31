// Package sip holds the SIP protocol primitives the FreeSBC edge
// needs: nil-safe header accessors, the header edits a
// dialog-touching element performs, transport-address parsing, RFC 3261
// request construction (branch parameters, CANCEL, teardown ACK/BYE) and the
// transport read-filter wrapper.
//
// It imports nothing from this module. That is the point: everything here is a
// transcription of RFC 3261/3264 with no policy of its own. Anything
// that encodes what THIS SBC decides — which codecs it relays, which peers
// it trusts, how it routes — belongs in the package that decides it.
package sip
