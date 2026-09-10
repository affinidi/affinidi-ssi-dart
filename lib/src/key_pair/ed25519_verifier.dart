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
// subgroup E[8] (points P with 8P = identity, including the identity itself),
// cross-checked against the libsodium/ref10 low-order blacklist and its
// canonical sign variants.
final _smallOrderPoints = <String>[
  '0100000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
].map(_decodeSmallOrderPoint).toList(growable: false);

Uint8List _decodeSmallOrderPoint(String encodedPoint) {
  final point = hexDecode(encodedPoint);
  if (point.length != ed.VerifyKey.keyLength) {
    throw StateError('Invalid Ed25519 small-order point length');
  }
  return point;
}

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
    return ed.VerifyKey(
      publicKey,
    ).verify(signature: ed.Signature(signature), message: message);
  } catch (_) {
    return false;
  }
}

bool _isSmallOrderPoint(Uint8List point) {
  var matchingCandidates = 0;
  for (final candidate in _smallOrderPoints) {
    var difference = 0;
    for (var index = 0; index < ed.VerifyKey.keyLength; index++) {
      difference |= point[index] ^ candidate[index];
    }
    matchingCandidates |= difference == 0 ? 1 : 0;
  }
  return matchingCandidates != 0;
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
