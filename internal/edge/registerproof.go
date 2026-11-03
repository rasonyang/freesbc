package edge

import "strings"

// What a 2xx to a public REGISTER must prove before FreeSBC acts on it
// (issue #303). The binding in Location is admission state: its source may
// place INVITEs, and the strike clearing below forgives a brute force. Both
// follow the request, not the registrar's 200, because a registrar can answer
// 200 to a query, to a blind registration, or to an identity other than the
// AoR the request names.
//
// A binding is recorded or refreshed only when the REGISTER had a Contact and
// either (a) carried an Authorization or Proxy-Authorization whose digest
// username equals the To user (case-insensitive; any username when
// edge.allow_register_auth_mismatch is set), or (b) refreshes a live binding
// of the same AoR and Call-ID held by the same source key (refreshesBinding).
// The 2xx from the registrar is the proof the digest was valid, so the nonce
// need not be one FreeSBC relayed. Strikes (StrikeRegister, StrikeAdmission,
// the AoR's) are cleared only in case (a): a credential-less refresh refreshes
// the binding and clears nothing. Un-REGISTER and wildcard un-REGISTER are not
// new bindings and are untouched. The response is relayed unchanged in every
// case; only FreeSBC's own state is withheld.

// bindingReject is why a 2xx REGISTER recorded no binding.
type bindingReject int

const (
	// rejectBindingNoContact: the REGISTER had no Contact (a query).
	rejectBindingNoContact bindingReject = iota
	// rejectBindingNoAuth: no credential and not a refresh of a live binding.
	rejectBindingNoAuth
	// rejectBindingAuthMismatch: the digest username is not the To user.
	rejectBindingAuthMismatch
	numBindingRejects
)

// bindingRejectLabels are the metric labels of freesbc_edge_register_binding_
// rejected_total.
var bindingRejectLabels = [numBindingRejects]string{
	rejectBindingNoContact:    "no_contact",
	rejectBindingNoAuth:       "no_auth",
	rejectBindingAuthMismatch: "auth_aor_mismatch",
}

func (r bindingReject) String() string { return bindingRejectLabels[r] }

// credentialMatches reports case (a): the request carried a credential for
// the AoR it registers (or any credential, under
// edge.allow_register_auth_mismatch, which is restart-only and so read from
// the snapshot the edge was built from).
func (s *Server) credentialMatches(in bindingInput) bool {
	if !in.head.Auth {
		return false
	}
	if s.boot.Edge.AllowRegisterAuthMismatch {
		return true
	}
	return in.head.User != "" && strings.EqualFold(in.head.User, in.user)
}

// bindingProof decides whether a 2xx to in may record or refresh a binding,
// and if not, why.
func (s *Server) bindingProof(in bindingInput) (bindingReject, bool) {
	switch {
	case !in.hasContact:
		return rejectBindingNoContact, false
	case s.credentialMatches(in):
		return 0, true
	case s.refreshesBinding(in.source.Addr().Unmap(), in.aor, in.callID):
		return 0, true
	case in.head.Auth:
		return rejectBindingAuthMismatch, false
	default:
		return rejectBindingNoAuth, false
	}
}

// rejectBinding counts and logs one 2xx that recorded no binding. The log
// carries the AoR, the source and, for a mismatch, the digest username (an
// identity, not a secret); never the response, the nonce or any hash.
func (s *Server) rejectBinding(in bindingInput, why bindingReject) {
	s.metrics.RegisterBindingRejected(why)
	attrs := []any{"aor", in.aor, "transport", in.transport,
		"public_remote", in.source.String(), "reason", why.String()}
	if why == rejectBindingAuthMismatch {
		attrs = append(attrs, "auth_user", in.head.User)
	}
	if why == rejectBindingNoContact {
		// A query never asked for a binding, and a registrar answers one
		// 2xx only after authenticating it: expected, not a warning.
		s.log.Debug("registration binding not recorded", attrs...)
		return
	}
	s.log.Warn("registration binding not recorded", attrs...)
}
