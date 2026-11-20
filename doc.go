// Package koloid provides Ed25519 node identities for Kolo.
// Only the 32-byte seed is stored on disk.
//
// A person with several devices has a recovery phrase of 24 words (BIP-39), a person key derived from it
// (SLIP-0010), one random key per device and a certificate for each device signed by the person key or by an
// approver device. A verifier states the person it expects and calls [VerifyDevice]; a revoked device is voided
// with [Identity.RevokeDevice]. The phrase is shown once and never stored by the library.
//
// Experimental: the API may change before v1.0.0.
package koloid
