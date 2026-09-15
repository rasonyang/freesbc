// Package sip holds the SIP protocol primitives both FreeSBC signaling
// planes need: nil-safe header accessors, the header edits a
// dialog-touching element performs, transport-address parsing, RFC 3261
// request construction (branch parameters, CANCEL, teardown ACK/BYE), the
// transport read-filter wrapper and a self-signed TLS identity.
//
// It imports nothing from this module. That is the point: the proxy plane
// and the trunk plane share protocol, never workflow, so everything here
// is a transcription of RFC 3261/3264 with no policy of its own. Anything
// that encodes what THIS SBC decides — which codecs it relays, which peers
// it trusts, how it routes — belongs in the plane that decides it.
package sip
