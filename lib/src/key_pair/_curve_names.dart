/// Supported elliptic curve names for cryptographic operations.
/// - [SEC1 v2.0, Section 2.3.3: Point Compression](https://www.secg.org/sec1-v2.pdf)
/// - [NIST Key Length Recommendations](https://csrc.nist.gov/projects/key-management/key-management-guidelines)
///
enum CurveName {
  /// - secp256r1 (NIST P-256): [NIST FIPS 186-4, Section D.1.2.3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
  secp256r1('secp256r1'),

  /// - secp256k1: [SEC2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf)
  secp256k1('secp256k1'),

  /// - secp384r1 (NIST P-384): [NIST FIPS 186-4, Section D.1.2.4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
  secp384r1('secp384r1'),

  /// - secp521r1 (NIST P-521): [NIST FIPS 186-4, Section D.1.2.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
  secp521r1('secp521r1'),

  /// - ed25519: [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://datatracker.ietf.org/doc/html/rfc8032)
  ed25519('ed25519'),

  /// - x25519: [RFC 7748: Elliptic Curves for Security](https://datatracker.ietf.org/doc/html/rfc7748)
  x25519('x25519');

  /// The string representation of the curve name.
  final String name;

  const CurveName(this.name);
}

/// Maps CurveName to the size (in bytes) of an uncompressed public key, including the leading format byte (0x04).
///
/// For NIST and secp curves, the uncompressed format is [0x04 | X | Y].
/// For Ed25519 and X25519, the public key is always 32 bytes.
///
/// References:
/// - [SEC1 v2.0, Section 2.3.3](https://www.secg.org/sec1-v2.pdf)
/// - [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)
/// - [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748)
final Map<CurveName, int> uncompressedPublicKeySizesWithLeadingByte = {
  CurveName.secp256r1: 65,
  CurveName.secp256k1: 65,
  CurveName.secp384r1: 97,
  CurveName.secp521r1: 133,
  CurveName.ed25519: 32,
  CurveName.x25519: 32,
};
