import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:elliptic/elliptic.dart' as elliptic;

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

bool isUri(String uri) => Uri.tryParse(uri) != null;

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
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(encodeBigInt(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(encodeBigInt(pub.Y)));
  } else if (indicatorHex == 'E701') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'secp256k1';
    var c = elliptic.getSecp256k1();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(encodeBigInt(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(encodeBigInt(pub.Y)));
  } else if (indicatorHex == '8124') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-384';
    var c = elliptic.getP384();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(encodeBigInt(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(encodeBigInt(pub.Y)));
  } else if (indicatorHex == '8224') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-521';
    var c = elliptic.getP521();
    var pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = removePaddingFromBase64(base64UrlEncode(encodeBigInt(pub.X)));
    jwk['y'] = removePaddingFromBase64(base64UrlEncode(encodeBigInt(pub.Y)));
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
      decodeBigInt(base64Decode(addPaddingToBase64(jwk['x']))),
      decodeBigInt(base64Decode(addPaddingToBase64(jwk['y']))),
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

/// Returns a decoded varint staring at the first byte of [varint] and the
/// number of bytes read.
(Uint8List decoded, int readBytes) decodeVarint(
  Uint8List varint, {
  int start = 0,
}) {
  if (varint.isEmpty || start >= varint.length) {
    throw FormatException('Empty input');
  }

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

  var i = start + 1;
  int leftOver = varint[start] & 0x7F;
  var leftOverLen = 7;

  var hasNext = (varint[start] & 0x80) > 0;
  while (hasNext && i < varint.length) {
    final packedByte = varint[i] & 0x7F;

    final byte = leftOver | ((packedByte & masks[leftOverLen]!) << leftOverLen);
    intValue.insert(0, byte);

    leftOver = packedByte >> (8 - leftOverLen);
    leftOverLen -= 1;

    hasNext = (varint[i] & 0x80) > 0;
    i++;

    if (leftOverLen == 0 && i < varint.length - 1 && hasNext) {
      leftOver = varint[i + 1];
      leftOverLen = 7;
      i++;
    }
  }
  if (leftOver > 0) {
    intValue.insert(0, leftOver);
  }

  if (hasNext) {
    throw FormatException('End reached without complete varint');
  }

  final readBytes = i - start;
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

final b256 = BigInt.from(256);

Uint8List encodeBigInt(BigInt number) {
  // see https://github.com/dart-lang/sdk/issues/32803
  // Not handling negative numbers. Decide how you want to do that.
  int bytes = (number.bitLength + 7) >> 3;

  var result = Uint8List(bytes);
  for (int i = 0; i < bytes; i++) {
    result[bytes - 1 - i] = number.remainder(b256).toInt();
    number = number >> 8;
  }

  return result;
}

BigInt decodeBigInt(Uint8List bytes) {
  // see https://github.com/dart-lang/sdk/issues/32803
  BigInt result = BigInt.zero;

  for (final byte in bytes) {
    // reading in big-endian, so we essentially concat the new byte to the end
    result = (result << 8) | BigInt.from(byte & 0xff);
  }

  return result;
}
