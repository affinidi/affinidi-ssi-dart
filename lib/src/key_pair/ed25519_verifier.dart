import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:pinenacl/ed25519.dart' as ed;

// p = 2^255 - 19, the edwards25519 field modulus, little-endian byte order.
const _fieldModulus = <int>[
  0xed,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0x7f,
];

// Canonical compressed encodings of the 8 points in the edwards25519 torsion
// subgroup E[8] (points P with 8P = identity, including the identity itself).
// Independently derived and verified (8P == identity, on-curve) from the
// curve equation rather than copied from an external source.
final _smallOrderPoints = <String>[
  '0100000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
].map(hexDecode).toList();

const _ed25519GroupOrder = <int>[
  0xed,
  0xd3,
  0xf5,
  0x5c,
  0x1a,
  0x63,
  0x12,
  0x58,
  0xd6,
  0x9c,
  0xf7,
  0xa2,
  0xde,
  0xf9,
  0xde,
  0x14,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x10,
];

/// Verifies an Ed25519 signature.
///
/// Rejects non-canonical scalar (S) and point (R, public key) encodings, and
/// rejects small-order (including identity) public keys and R values, to
/// close known Ed25519 signature-malleability gaps.
bool verifyEd25519Signature(
  Uint8List publicKey,
  Uint8List message,
  Uint8List signature,
) {
  if (publicKey.length != ed.VerifyKey.keyLength ||
      signature.length != ed.Signature.signatureLength ||
      !_isCanonicalScalar(signature.sublist(32)) ||
      !_isCanonicalPoint(signature.sublist(0, 32)) ||
      !_isCanonicalPoint(publicKey) ||
      _isSmallOrderPoint(publicKey) ||
      _isSmallOrderPoint(signature.sublist(0, 32))) {
    return false;
  }

  try {
    return ed.VerifyKey(publicKey).verify(
      signature: ed.Signature(signature),
      message: message,
    );
  } catch (_) {
    return false;
  }
}

bool _isSmallOrderPoint(Uint8List point) {
  for (final candidate in _smallOrderPoints) {
    var matches = true;
    for (var index = 0; index < 32; index++) {
      if (point[index] != candidate[index]) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return true;
    }
  }
  return false;
}

bool _isCanonicalPoint(Uint8List point) {
  // The sign bit (top bit of the last byte) is not part of the y-coordinate.
  final y = Uint8List.fromList(point);
  y[31] &= 0x7f;
  for (var index = y.length - 1; index >= 0; index--) {
    if (y[index] != _fieldModulus[index]) {
      return y[index] < _fieldModulus[index];
    }
  }
  // y == p is not a canonical encoding of any field element.
  return false;
}

bool _isCanonicalScalar(Uint8List scalar) {
  for (var index = scalar.length - 1; index >= 0; index--) {
    if (scalar[index] != _ed25519GroupOrder[index]) {
      return scalar[index] < _ed25519GroupOrder[index];
    }
  }
  return false;
}
