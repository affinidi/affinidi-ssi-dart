import 'dart:typed_data';

import 'package:x25519/src/curve25519.dart' as x25519;
import 'package:base_codecs/base_codecs.dart';

//ported from https://github.com/oasisprotocol/ed25519/blob/master/extra/x25519/x25519.go
String ed25519PublicToX25519Public(List<int> ed25519Public) {
  var Y = x25519.FieldElement();
  x25519.feFromBytes(Y, ed25519Public);
  var oneMinusY = x25519.FieldElement();
  x25519.FeOne(oneMinusY);
  x25519.FeSub(oneMinusY, oneMinusY, Y);
  x25519.feInvert(oneMinusY, oneMinusY);

  var outX = x25519.FieldElement();
  x25519.FeOne(outX);
  x25519.FeAdd(outX, outX, Y);

  x25519.feMul(outX, outX, oneMinusY);

  var dst = List.filled(32, 0);
  x25519.FeToBytes(dst, outX);

  const xMultiCodec = [236, 1];

  return base58Bitcoin.encode(Uint8List.fromList(xMultiCodec + dst));
}
