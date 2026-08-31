import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;

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

/// Verifies an Ed25519 signature and rejects non-canonical scalar encodings.
bool verifyEd25519Signature(
  Uint8List publicKey,
  Uint8List message,
  Uint8List signature,
) {
  if (publicKey.length != ed.VerifyKey.keyLength ||
      signature.length != ed.Signature.signatureLength ||
      !_isCanonicalScalar(signature.sublist(32))) {
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

bool _isCanonicalScalar(Uint8List scalar) {
  for (var index = scalar.length - 1; index >= 0; index--) {
    if (scalar[index] != _ed25519GroupOrder[index]) {
      return scalar[index] < _ed25519GroupOrder[index];
    }
  }
  return false;
}
