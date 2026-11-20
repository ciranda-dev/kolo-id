package keyfile

import (
	"encoding/binary"
	"encoding/hex"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ACE flags as in xnu bsd/sys/kauth.h: the low 4 bits are the kind, 0x10 is INHERITED, 0x20 FILE_INHERIT.
const aceDeny, acePermit, acePermitInherit, acePermitInherited, aceDenyInherited, aceAudit = 2, 1, 0x21, 0x11, 0x12, 3

// aclReply builds an fgetattrlist reply holding a kauth_filesec with the given ACE kinds.
func aclReply(kinds ...uint32) []byte {
	ne := binary.NativeEndian
	sec := make([]byte, 44+24*len(kinds))
	ne.PutUint32(sec, 0x012cc16d)
	ne.PutUint32(sec[36:], uint32(len(kinds)))
	for i, k := range kinds {
		ne.PutUint32(sec[44+24*i+16:], k)
	}
	b := make([]byte, 32, 32+len(sec))
	b = append(b, sec...)
	ne.PutUint32(b, uint32(len(b)))
	ne.PutUint32(b[4:], unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_EXTENDED_SECURITY)
	ne.PutUint32(b[24:], 8) // the data follows the attrreference at offset 24
	ne.PutUint32(b[28:], uint32(len(sec)))
	return b
}

func withU32(b []byte, at int, v uint32) []byte {
	b = append([]byte(nil), b...)
	binary.NativeEndian.PutUint32(b[at:], v)
	return b
}

// Replies fgetattrlist gave on APFS (macOS 26): a file with no ACL, and one with "everyone allow read".
const (
	apfsNoACL = "2000000000000080000000000000000000000000000000000000000000000000"
	apfsAllow = "6400000000004080000000000000000000000000000000000800000044000000" +
		"6dc12c01000000000000000000000000000000000000000000000000000000000000000001000000" +
		"00000000abcdefabcdefabcdefabcdef0000000c0100000002000000"
)

func mustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func repeatKind(k uint32, n int) []uint32 {
	kinds := make([]uint32, n)
	for i := range kinds {
		kinds[i] = k
	}
	return kinds
}

func TestACLReplyAllows(t *testing.T) {
	deny := aclReply(aceDeny)
	unaligned := append(append([]byte(nil), deny...), 0, 0, 0)
	binary.NativeEndian.PutUint32(unaligned, uint32(len(deny)+1))
	for _, tc := range []struct {
		name      string
		r1, errno uintptr
		reply     []byte
		want      bool
	}{
		{"APFS reply without an ACL", 0, 0, mustDecode(apfsNoACL), false},
		{"APFS reply with an allow entry", 0, 0, mustDecode(apfsAllow), true},
		{"call failed", 0, uintptr(syscall.EIO), deny, true},
		{"nonzero r1", 1, 0, deny, true},
		{"short reply", 0, 0, deny[:10], true},
		{"length beyond the buffer", 0, 0, withU32(deny, 0, uint32(len(deny)+1)), true},
		{"length below the header", 0, 0, withU32(deny, 0, 8), true},
		{"length not 4-byte aligned", 0, 0, unaligned, true},
		{"returned bitmap without ATTR_CMN_RETURNED_ATTRS", 0, 0, withU32(deny, 4, unix.ATTR_CMN_EXTENDED_SECURITY), true},
		{"returned bitmap with an unrequested common bit", 0, 0, withU32(deny, 4, unix.ATTR_CMN_RETURNED_ATTRS|unix.ATTR_CMN_EXTENDED_SECURITY|unix.ATTR_CMN_NAME), true},
		{"returned bitmap with a volume attribute", 0, 0, withU32(deny, 8, 1), true},
		{"returned bitmap with a fork attribute", 0, 0, withU32(deny, 20, 1), true},
		{"not supported by the filesystem", 0, 0, withU32(withU32(deny[:24], 0, 24), 4, unix.ATTR_CMN_RETURNED_ATTRS), false},
		{"returned without the attrreference", 0, 0, withU32(deny[:28], 0, 28), true},
		{"zero-length attrreference", 0, 0, withU32(deny, 28, 0), true},
		{"KAUTH_FILESEC_NOACL", 0, 0, withU32(aclReply(), 32+36, 0xffffffff), false},
		{"KAUTH_FILESEC_NOACL with room for entries", 0, 0, withU32(deny, 32+36, 0xffffffff), true},
		{"deny only", 0, 0, deny, false},
		{"inherited deny", 0, 0, aclReply(aceDenyInherited), false},
		{"empty ACL", 0, 0, aclReply(), false},
		{"128 deny entries", 0, 0, aclReply(repeatKind(aceDeny, 128)...), false},
		{"permit", 0, 0, aclReply(acePermit), true},
		{"permit with file_inherit", 0, 0, aclReply(acePermitInherit), true},
		{"inherited permit", 0, 0, aclReply(acePermitInherited), true},
		{"permit at the last index", 0, 0, aclReply(aceDeny, aceDeny, acePermit), true},
		{"unknown ACE kind (audit)", 0, 0, aclReply(aceAudit), true},
		{"ACE kind zero", 0, 0, aclReply(0), true},
		{"count too large for the length", 0, 0, withU32(deny, 32+36, 2), true},
		{"length larger than the count needs", 0, 0, withU32(aclReply(aceDeny, aceDeny), 32+36, 1), true},
		{"count above KAUTH_ACL_MAX_ENTRIES", 0, 0, aclReply(repeatKind(aceDeny, 129)...), true},
		{"offset into the header", 0, 0, withU32(deny, 24, 0), true},
		{"offset into the attrreference", 0, 0, withU32(deny, 24, 4), true},
		{"negative offset", 0, 0, withU32(deny, 24, 0xfffffff8), true},
		{"overflowing offset", 0, 0, withU32(deny, 24, 0x7fffffff), true},
		{"data beyond the reply length", 0, 0, withU32(deny, 28, uint32(len(deny))), true},
		{"data shorter than the filesec header", 0, 0, withU32(deny, 28, 40), true},
		{"wrong magic", 0, 0, withU32(deny, 32, 0x12345678), true},
	} {
		if got := aclReplyAllows(tc.r1, tc.errno, tc.reply); got != tc.want {
			t.Errorf("%s: aclReplyAllows = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func FuzzACLReply(f *testing.F) {
	f.Add(aclReply(aceDeny), uint(0), uint(0))
	f.Add(aclReply(aceDeny, acePermit), uint(0), uint(0))
	f.Add(aclReply(), uint(0), uint(0))
	f.Add(mustDecode(apfsNoACL), uint(0), uint(0))
	f.Add([]byte{}, uint(0), uint(0))
	f.Fuzz(func(t *testing.T, b []byte, r1, errno uint) {
		got := aclReplyAllows(uintptr(r1), uintptr(errno), b)
		if again := aclReplyAllows(uintptr(r1), uintptr(errno), b); again != got {
			t.Fatalf("the same reply gave %v, then %v", got, again)
		}
		if (r1 != 0 || errno != 0) && !got {
			t.Fatalf("a failed call (r1 %d, errno %d) was accepted", r1, errno)
		}
		if len(b) >= 4 && int(binary.NativeEndian.Uint32(b)) <= len(b) {
			if again := aclReplyAllows(uintptr(r1), uintptr(errno), append(b[:len(b):len(b)], 0xff, 0xff, 0xff, 0xff)); again != got {
				t.Fatalf("bytes past the reply length changed the result from %v to %v", got, again)
			}
		}
	})
}
