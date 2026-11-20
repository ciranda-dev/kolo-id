package koloid

import "github.com/ciranda-dev/kolo-id/internal/keyfile"

// SaveCert atomically replaces path with the encoding of c, mode 0600, with the same directory checks as [Identity.Save].
// Keep the certificate next to the device key, for example "device.cert" beside "device.key". It does not verify c.
func SaveCert(path string, c *DeviceCert) error {
	if c == nil {
		return badCert("no certificate")
	}
	if err := c.body.check(c.parent); err != nil {
		return err
	}
	return keyfile.WriteBlob(path, c.Encode(), true)
}

// LoadCert reads a certificate written by [SaveCert] with the checks of [Load]; the result is untrusted until [VerifyDevice] or [DeviceCert.Verify].
// An empty or over-514-byte file is [ErrInvalidKeyFile]; bytes that do not decode are [ErrInvalidCert].
func LoadCert(path string) (*DeviceCert, error) {
	b, err := keyfile.ReadBlob(path, maxCertWithParent)
	if err != nil {
		return nil, err
	}
	return DecodeDeviceCert(b)
}
