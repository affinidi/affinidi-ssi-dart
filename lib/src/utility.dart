import 'dart:math';
import 'dart:typed_data';

// ignore: implementation_imports
import 'package:x25519/src/curve25519.dart' as x25519;

/// Converts an Ed25519 public key to an X25519 public key.
///
/// Returns a X25519 public key as a Uint8List.
/// Ported from https://github.com/oasisprotocol/ed25519/blob/master/extra/x25519/x25519.go
Uint8List ed25519PublicToX25519Public(List<int> ed25519Public) {
  final Y = x25519.FieldElement();
  x25519.feFromBytes(Y, ed25519Public);
  final oneMinusY = x25519.FieldElement();
  x25519.FeOne(oneMinusY);
  x25519.FeSub(oneMinusY, oneMinusY, Y);
  x25519.feInvert(oneMinusY, oneMinusY);

  final outX = x25519.FieldElement();
  x25519.FeOne(outX);
  x25519.FeAdd(outX, outX, Y);

  x25519.feMul(outX, outX, oneMinusY);

  final dst = List.filled(32, 0);
  x25519.FeToBytes(dst, outX);

  return Uint8List.fromList(dst);
}

/// Generates a random identifier as a hexadecimal string.
///
/// Returns a 32-character string consisting of random hexadecimal digits.
String randomId() {
  final rnd = Random.secure();
  return List.generate(32, (idx) => rnd.nextInt(16).toRadixString(16)).join();
}
