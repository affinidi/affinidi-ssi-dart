import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/tweetnacl.dart';

/// Converts an Ed25519 public key to an X25519 public key.
///
/// Returns a X25519 public key as a Uint8List.
/// Ported from https://github.com/oasisprotocol/ed25519/blob/master/extra/x25519/x25519.go
Uint8List ed25519PublicToX25519Public(List<int> ed25519Public) {
  if (ed25519Public.length != 32) {
    throw ArgumentError.value(
      ed25519Public,
      'ed25519Public',
      'Ed25519 public keys must contain 32 bytes',
    );
  }

  final x25519Public = Uint8List(32);
  final result = TweetNaClExt.crypto_sign_ed25519_pk_to_x25519_pk(
    x25519Public,
    Uint8List.fromList(ed25519Public),
  );
  if (result != 0) {
    throw ArgumentError.value(
      ed25519Public,
      'ed25519Public',
      'Invalid Ed25519 public key',
    );
  }

  return x25519Public;
}

/// Generates a random identifier as a hexadecimal string.
///
/// Returns a 32-character string consisting of random hexadecimal digits.
String randomId() {
  final rnd = Random.secure();
  return List.generate(32, (idx) => rnd.nextInt(16).toRadixString(16)).join();
}
