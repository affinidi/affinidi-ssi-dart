import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:pointycastle/src/utils.dart' as p_utils;

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';

enum MultiBase {
  base58bitcoin,
  base64UrlNoPad,
}

Uint8List multiBaseToUint8List(String multibase) {
  if (multibase.isEmpty) {
    throw SsiException(
      message: 'Empty multi-base',
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }

  final indicator = multibase[0];
  final encodedData = multibase.substring(1);
  switch (indicator) {
    case 'z':
      return base58BitcoinDecode(encodedData);

    case 'u':
      return base64Url.decode(encodedData);

    default:
      throw UnimplementedError(
        'Unsupported multibase indicator ${multibase[0]}',
      );
  }
}

String toMultiBase(
  Uint8List multibase, {
  MultiBase base = MultiBase.base58bitcoin,
}) {
  switch (base) {
    case MultiBase.base58bitcoin:
      return 'z${base58BitcoinEncode(multibase)}';

    case MultiBase.base64UrlNoPad:
      return 'u${removePaddingFromBase64(base64UrlEncode(multibase))}';
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

Map<String, dynamic> multiKeyToJwk(Uint8List multikey) {
  final indicator = multikey.sublist(0, 2);
  final key = multikey.sublist(2);

  final indicatorHex = hex.encode(indicator);

  // see https://www.w3.org/TR/cid-1.0/#Multikey for indicators
  // FIXME add validations for length
  Map<String, dynamic> jwk = {};
  if (indicatorHex == 'ED01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'Ed25519';
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(key));
  } else if (indicatorHex == 'EC01') {
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

Uint8List jwkToMultiKey(Map<String, dynamic> jwk) {
  var crv = jwk['crv'];

  switch (crv) {
    case 'Ed25519':
      return Uint8List.fromList(
        MultiKeyIndicator.ed25519.indicator +
            base64Decode(
              addPaddingToBase64(jwk['x']),
            ),
      );

    case 'secp256k1':
    case 'P-256K':
      return _ecJwkToMultiKey(
        jwk: jwk,
        curve: elliptic.getSecp256k1(),
        multikeyIndicator: MultiKeyIndicator.secp256k1.indicator,
      );

    case 'P-256':
      return _ecJwkToMultiKey(
        jwk: jwk,
        curve: elliptic.getP256(),
        multikeyIndicator: MultiKeyIndicator.p256.indicator,
      );

    case 'P-384':
      return _ecJwkToMultiKey(
        jwk: jwk,
        curve: elliptic.getP384(),
        multikeyIndicator: MultiKeyIndicator.p384.indicator,
      );

    case 'P-521':
      return _ecJwkToMultiKey(
        jwk: jwk,
        curve: elliptic.getP521(),
        multikeyIndicator: MultiKeyIndicator.p521.indicator,
      );

    default:
      throw SsiException(
        message: 'jwkToMultikey: unsupported curve $crv',
        code: SsiExceptionType.other.code,
      );
  }
}

Uint8List _ecJwkToMultiKey({
  required elliptic.Curve curve,
  required Map<String, dynamic> jwk,
  required List<int> multikeyIndicator,
}) {
  var compressedHex = curve.publicKeyToCompressedHex(
    elliptic.PublicKey(
      curve,
      bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['x']))),
      bytesToUnsignedInt(base64Decode(addPaddingToBase64(jwk['y']))),
    ),
  );
  var compressedBytes = hexDecode(compressedHex);
  return Uint8List.fromList(
    multikeyIndicator + compressedBytes,
  );
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

enum MultiKeyIndicator {
  x25519(KeyType.x25519, [0xEC, 0x01]),
  ed25519(KeyType.ed25519, [0xED, 0x01]),
  secp256k1(KeyType.secp256k1, [0xE7, 0x01]),
  p256(KeyType.p256, [0x80, 0x24]),
  p384(KeyType.p384, [0x81, 0x24]),
  p521(KeyType.p521, [0x82, 0x24]);

  final List<int> indicator;
  final KeyType keyType;

  const MultiKeyIndicator(this.keyType, this.indicator);
}

final Map<KeyType, MultiKeyIndicator> keyIndicators = _initKeyIndicatorsMap();

Map<KeyType, MultiKeyIndicator> _initKeyIndicatorsMap() {
  final Map<KeyType, MultiKeyIndicator> map = {};
  for (final keyIndicator in MultiKeyIndicator.values) {
    map[keyIndicator.keyType] = keyIndicator;
  }
  return map;
}

Uint8List toMultikey(
  Uint8List pubKeyBytes,
  KeyType keyType,
) {
  if (!keyIndicators.containsKey(keyType)) {
    throw SsiException(
      message: "toMultikey: $keyType not supported",
      code: SsiExceptionType.other.code,
    );
  }
  final indicator = keyIndicators[keyType]!;
  return Uint8List.fromList([...indicator.indicator, ...pubKeyBytes]);
}
