package keyfile

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// From xnu bsd/sys/kauth.h; x/sys/unix does not define them.
const (
	kauthFilesecMagic  = 0x012cc16d // KAUTH_FILESEC_MAGIC
	kauthFilesecNoACL  = 0xffffffff // KAUTH_FILESEC_NOACL
	kauthACLMaxEntries = 128        // KAUTH_ACL_MAX_ENTRIES
	kauthACEKindMask   = 0xf        // KAUTH_ACE_KINDMASK
	kauthACEPermit     = 1          // KAUTH_ACE_PERMIT
	kauthACEDeny       = 2          // KAUTH_ACE_DENY
)

// aclReplyAllows reports whether an fgetattrlist call for ATTR_CMN_RETURNED_ATTRS and
// ATTR_CMN_EXTENDED_SECURITY found an ACL entry that allows access.
// A failed call or any reply that is not exactly the expected layout counts as allowing.
func aclReplyAllows(r1, errno uintptr, reply []byte) bool {
	if r1 != 0 || errno != 0 {
		return true
	}
	ne := binary.NativeEndian
	// u_int32 length, attribute_set_t returned (5 x u_int32), then an attrreference_t at 24.
	const setAt, refAt, refEnd = 4, 24, 32
	if len(reply) < refAt {
		return true
	}
	length := int64(ne.Uint32(reply))
	if length < refAt || length > int64(len(reply)) || length%4 != 0 {
		return true
	}
	common := ne.Uint32(reply[setAt:])
	if common&unix.ATTR_CMN_RETURNED_ATTRS == 0 || common&^(unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_EXTENDED_SECURITY) != 0 {
		return true
	}
	for at := setAt + 4; at < refAt; at += 4 { // volattr, dirattr, fileattr, forkattr
		if ne.Uint32(reply[at:]) != 0 {
			return true
		}
	}
	// APFS and HFS+ leave EXTENDED_SECURITY out of the returned set when a file has no ACL,
	// so its absence means no ACL; a filesystem without ACL support reports the same.
	if common&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		return false
	}
	if length < refEnd {
		return true
	}
	off, n := int64(int32(ne.Uint32(reply[refAt:]))), int64(ne.Uint32(reply[refAt+4:]))
	const header, entry = 44, 24 // kauth_filesec up to fsec_acl.acl_ace, and one kauth_ace
	start := refAt + off         // the offset is relative to the attrreference_t
	if start < refEnd || n < header || start+n > length {
		return true
	}
	sec := reply[start : start+n]
	if ne.Uint32(sec) != kauthFilesecMagic {
		return true
	}
	count := ne.Uint32(sec[36:])
	if count == kauthFilesecNoACL {
		return n != header
	}
	if count > kauthACLMaxEntries || n != header+entry*int64(count) {
		return true
	}
	for i := range int64(count) {
		if ne.Uint32(sec[header+i*entry+16:])&kauthACEKindMask != kauthACEDeny {
			return true // an allow entry, or a kind this check does not know
		}
	}
	return false
}
