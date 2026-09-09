import 'dart:typed_data';

import 'package:ssi/src/utility.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('When converting an Ed25519 public key to X25519', () {
    test('it ignores bytes after the 32-byte public key', () {
      final keyPair = Ed25519KeyPair.fromSeed(Uint8List(32));
      final publicKey = keyPair.publicKey.bytes;
      final oversizedPublicKey = [...publicKey, 1, 2, 3];

      expect(
        ed25519PublicToX25519Public(oversizedPublicKey),
        ed25519PublicToX25519Public(publicKey),
      );
    });
  });
}
