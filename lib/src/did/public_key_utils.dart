import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:pointycastle/src/utils.dart' as p_utils;

Uint8List _multibaseToUint8List(String multibase) {
  if (multibase.startsWith('z')) {
    return base58BitcoinDecode(multibase.substring(1));
  } else {
    throw UnimplementedError('Unsupported multibase indicator ${multibase[0]}');
  }
}

bool isUri(String uri) {
  try {
    Uri.parse(uri);
    return true;
  } catch (_) {
    return false;
  }
}

String multibaseToBase64Url(String multibase) {
  return base64UrlEncode(_multibaseToUint8List(multibase));
}

Map<String, dynamic> multibaseKeyToJwk(String multibaseKey) {
  var key = _multibaseToUint8List(multibaseKey);
  var indicator = key.sublist(0, 2);

  switch (indicator) {
    case [0xED, 0x01]:
  }
  var indicatorHex = bytesToHex(indicator);
  key = key.sublist(2);
  Map<String, dynamic> jwk = {};
  if (indicatorHex == 'ed01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'Ed25519';
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(key));
  } else if (indicatorHex == 'ec01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'X25519';
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(key));
  } else if (indicatorHex == '8024') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-256';
    var c = elliptic.getP256();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == 'E701') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'secp256k1';
    var c = elliptic.getSecp256k1();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == '8124') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-384';
    var c = elliptic.getP384();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else if (indicatorHex == '8224') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-521';
    var c = elliptic.getP521();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(
        pub.X < BigInt.zero ? intToBytes(pub.X) : unsignedIntToBytes(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(
        pub.Y < BigInt.zero ? intToBytes(pub.Y) : unsignedIntToBytes(pub.Y)));
  } else {
    throw UnimplementedError(
        'Unsupported multicodec indicator 0x$indicatorHex');
  }
  return jwk;
}

String jwkToMultiBase(Map<String, dynamic> jwk) {
  var crv = jwk['crv'];
  if (crv == 'Ed25519') {
    return 'z${base58BitcoinEncode(Uint8List.fromList([
          237,
          1
        ] + base64Decode(addPaddingToBase64(jwk['x']))))}';
  } else if (crv == 'P-256') {
    var c = elliptic.getP256();
    var compressedHex = c.publicKeyToCompressedHex(elliptic.PublicKey(
        c,
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['x']))),
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['y'])))));
    var compressedBytes = hexDecode(compressedHex);
    return 'z${base58BitcoinEncode(Uint8List.fromList([
          128,
          36
        ] + compressedBytes))}';
  } else if (crv == 'P-384') {
    var c = elliptic.getP384();
    var compressedHex = c.publicKeyToCompressedHex(elliptic.PublicKey(
        c,
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['x']))),
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['y'])))));
    var compressedBytes = hexDecode(compressedHex);
    return 'z${base58BitcoinEncode(Uint8List.fromList([
          129,
          36
        ] + compressedBytes))}';
  } else if (crv == 'P-521') {
    var c = elliptic.getP521();
    var compressedHex = c.publicKeyToCompressedHex(elliptic.PublicKey(
        c,
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['x']))),
        bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['y'])))));
    var compressedBytes = hexDecode(compressedHex);
    return 'z${base58BitcoinEncode(Uint8List.fromList([
          130,
          36
        ] + compressedBytes))}';
  } else {
    throw Exception('unsupported curve $crv');
  }
}

// if (keyType == KeyType.p521) {
// c = getP521();
// prefix = [130, 36];
// } else if (keyType == KeyType.p384) {
// c = getP384();
// prefix = [129, 36];
// } else {
// c = getP256();
// prefix = [128, 36];
// }

/// Converts json-String [credential] to dart Map.
Map<String, dynamic> credentialToMap(dynamic credential) {
  if (credential is String) {
    return jsonDecode(credential);
  } else if (credential is Map<String, dynamic>) {
    return credential;
  } else if (credential is Map<dynamic, dynamic>) {
    return credential.map((key, value) => MapEntry(key as String, value));
  } else {
    throw Exception(
        'Unknown datatype ${credential.runtimeType} for $credential. Only String or Map<String, dynamic> accepted');
  }
}

String addPaddingToBase64(String base64Input) {
  while (base64Input.length % 4 != 0) {
    base64Input += '=';
  }
  return base64Input;
}

String removePaddingFromBase64(String base64Input) {
  while (base64Input.endsWith('=')) {
    base64Input = base64Input.substring(0, base64Input.length - 1);
  }
  return base64Input;
}

/// If present, removes the 0x from the start of a hex-string.
String strip0x(String hex) {
  if (hex.startsWith('0x')) return hex.substring(2);
  return hex;
}

/// Converts the [bytes] given as a list of integers into a hexadecimal
/// representation.
///
/// If any of the bytes is outside of the range [0, 256], the method will throw.
/// The outcome of this function will prefix a 0 if it would otherwise not be
/// of even length. If [include0x] is set, it will prefix "0x" to the hexadecimal
/// representation. If [forcePadLength] is set, the hexadecimal representation
/// will be expanded with zeroes until the desired length is reached. The "0x"
/// prefix does not count for the length.
String bytesToHex(
  Uint8List bytes, {
  bool include0x = false,
  int? forcePadLength,
  bool padToEvenLength = false,
}) {
  var encoded = hex.encode(bytes);

  if (forcePadLength != null) {
    assert(forcePadLength >= encoded.length);

    final padding = forcePadLength - encoded.length;
    encoded = ('0' * padding) + encoded;
  }

  if (padToEvenLength && encoded.length % 2 != 0) {
    encoded = '0$encoded';
  }

  return (include0x ? '0x' : '') + encoded;
}

Uint8List unsignedIntToBytes(BigInt number) {
  assert(!number.isNegative);
  return p_utils.encodeBigIntAsUnsigned(number);
}

BigInt bytesToUnsignedInt(Uint8List bytes) {
  return p_utils.decodeBigIntWithSign(1, bytes);
}

Uint8List intToBytes(BigInt number) => p_utils.encodeBigInt(number);

/// Returns a decoded varint staring at the first byte of [varint] and the
/// number of bytes read.
(Uint8List, int) decodeVarint(
  Uint8List varint, {
  int start = 0,
}) {
  if (varint.isEmpty) {
    throw FormatException('Empty input');
  }

  List<int> content = [];
  int i = start;
  bool shouldContinue = true;
  while (i < varint.length && shouldContinue) {
    final value = varint[i] & 0x7F;
    content.insert(0, value);

    shouldContinue = (varint[i] & 0x80) > 0;
    i++;
  }
  final readBytes = i - start;

  Map<int, int> masks = {
    7: 0x01,
    6: 0x03,
    5: 0x07,
    4: 0x0F,
    3: 0x1F,
    2: 0x3F,
    1: 0x7F,
  };

  List<int> intValue = [];
  var leftOver = content[content.length - 1];
  var leftOverLen = 7;
  for (int i = content.length - 2; i >= 0; i--) {
    final packedByte = content[i];

    final byte = leftOver | ((packedByte & masks[leftOverLen]!) << leftOverLen);
    intValue.insert(0, byte);

    leftOver = packedByte >> (8 - leftOverLen);
    leftOverLen -= 1;

    if (leftOverLen == 0 && i > 0) {
      leftOver = content[i - 1];
      leftOverLen = 7;
      i--;
    }
  }
  if (leftOver > 0) {
    intValue.insert(0, leftOver);
  }

  return (Uint8List.fromList(intValue), readBytes);
}
