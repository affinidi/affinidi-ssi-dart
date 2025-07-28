import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:elliptic/elliptic.dart' as elliptic;

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../util/base64_util.dart';

/// Supported multibase encodings.
enum MultiBase {
  /// Base58 encoding using the Bitcoin alphabet.
  base58bitcoin,

  /// Base64 URL encoding without padding.
  base64UrlNoPad,
}

/// Converts a multibase string to a [Uint8List].
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
      return base64UrlNoPadDecode(encodedData);

    default:
      throw SsiException(
        message: 'Unsupported multibase indicator ${multibase[0]}',
        code: SsiExceptionType.invalidDidDocument.code,
      );
  }
}

/// Converts bytes to a multibase string.
String toMultiBase(
  Uint8List multibase, {
  MultiBase base = MultiBase.base58bitcoin,
}) {
  switch (base) {
    case MultiBase.base58bitcoin:
      return 'z${base58BitcoinEncode(multibase)}';

    case MultiBase.base64UrlNoPad:
      return 'u${base64UrlNoPadEncode(multibase)}';
  }
}

/// Checks if the given string is a valid URI.
bool isUri(String uri) => Uri.tryParse(uri) != null;

/// Converts a multikey to a JWK map.
Map<String, dynamic> multiKeyToJwk(Uint8List multikey) {
  final indicator = multikey.sublist(0, 2);
  final key = multikey.sublist(2);

  final indicatorHex = hex.encode(indicator);

  // see https://www.w3.org/TR/cid-1.0/#Multikey for indicators
  // FIXME add validations for length
  var jwk = <String, dynamic>{};
  if (indicatorHex == 'ED01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'Ed25519';
    jwk['x'] = base64UrlNoPadEncode(key);
  } else if (indicatorHex == 'EC01') {
    jwk['kty'] = 'OKP';
    jwk['crv'] = 'X25519';
    jwk['x'] = base64UrlNoPadEncode(key);
  } else if (indicatorHex == '8024') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-256';
    final c = elliptic.getP256();
    final pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = base64UrlNoPadEncode(encodeBigInt(pub.X));
    jwk['y'] = base64UrlNoPadEncode(encodeBigInt(pub.Y));
  } else if (indicatorHex == 'E701') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'secp256k1';
    final c = elliptic.getSecp256k1();
    final pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = base64UrlNoPadEncode(encodeBigInt(pub.X));
    jwk['y'] = base64UrlNoPadEncode(encodeBigInt(pub.Y));
  } else if (indicatorHex == '8124') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-384';
    final c = elliptic.getP384();
    final pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = base64UrlNoPadEncode(encodeBigInt(pub.X));
    jwk['y'] = base64UrlNoPadEncode(encodeBigInt(pub.Y));
  } else if (indicatorHex == '8224') {
    jwk['kty'] = 'EC';
    jwk['crv'] = 'P-521';
    final c = elliptic.getP521();
    final pub = c.compressedHexToPublicKey(hex.encode(key));
    jwk['x'] = base64UrlNoPadEncode(encodeBigInt(pub.X));
    jwk['y'] = base64UrlNoPadEncode(encodeBigInt(pub.Y));
  } else {
    throw SsiException(
      message: 'Unsupported multicodec indicator 0x$indicatorHex',
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }
  return jwk;
}

/// Converts a JWK map to a multikey.
Uint8List jwkToMultiKey(Map<String, dynamic> jwk) {
  final crv = jwk['crv'];

  switch (crv) {
    case 'Ed25519':
      return Uint8List.fromList(
        MultiKeyIndicator.ed25519.indicator + base64UrlNoPadDecode(jwk['x']),
      );
    case 'X25519':
      return Uint8List.fromList(
        MultiKeyIndicator.x25519.indicator + base64UrlNoPadDecode(jwk['x']),
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
  final compressedHex = curve.publicKeyToCompressedHex(
    elliptic.PublicKey(
      curve,
      decodeBigInt(base64UrlNoPadDecode(jwk['x'])),
      decodeBigInt(base64UrlNoPadDecode(jwk['y'])),
    ),
  );
  final compressedBytes = hexDecode(compressedHex);
  return Uint8List.fromList(
    multikeyIndicator + compressedBytes,
  );
}

/// Returns a decoded varint staring at the first byte of [varint] and the number of bytes read.
(Uint8List decoded, int readBytes) decodeVarint(
  Uint8List varint, {
  int start = 0,
}) {
  if (varint.isEmpty || start >= varint.length) {
    throw const FormatException('Empty input');
  }

  var masks = <int, int>{
    7: 0x01,
    6: 0x03,
    5: 0x07,
    4: 0x0F,
    3: 0x1F,
    2: 0x3F,
    1: 0x7F,
  };

  var intValue = <int>[];

  var i = start + 1;
  var leftOver = varint[start] & 0x7F;
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
    throw SsiException(
      message: 'End reached without complete varint',
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }

  final readBytes = i - start;
  return (Uint8List.fromList(intValue), readBytes);
}

/// Supported multikey indicators.
enum MultiKeyIndicator {
  /// Indicator for X25519 keys.
  x25519(KeyType.x25519, [0xEC, 0x01]),

  /// Indicator for Ed25519 keys.
  ed25519(KeyType.ed25519, [0xED, 0x01]),

  /// Indicator for secp256k1 keys.
  secp256k1(KeyType.secp256k1, [0xE7, 0x01]),

  /// Indicator for P-256 keys.
  p256(KeyType.p256, [0x80, 0x24]),

  /// Indicator for P-384 keys.
  p384(KeyType.p384, [0x81, 0x24]),

  /// Indicator for P-521 keys.
  p521(KeyType.p521, [0x82, 0x24]);

  /// The indicator bytes for the key type.
  final List<int> indicator;

  /// The key type.
  final KeyType keyType;

  /// Creates a [MultiKeyIndicator] instance.
  const MultiKeyIndicator(this.keyType, this.indicator);
}

/// Returns a map of [KeyType] to [MultiKeyIndicator].
final Map<KeyType, MultiKeyIndicator> keyIndicators = _initKeyIndicatorsMap();

/// Initializes the map of [KeyType] to [MultiKeyIndicator].
Map<KeyType, MultiKeyIndicator> _initKeyIndicatorsMap() {
  final map = <KeyType, MultiKeyIndicator>{};
  for (final keyIndicator in MultiKeyIndicator.values) {
    map[keyIndicator.keyType] = keyIndicator;
  }
  return map;
}

/// Converts a public key and key type to a multikey [Uint8List].
Uint8List toMultikey(
  Uint8List pubKeyBytes,
  KeyType keyType,
) {
  if (!keyIndicators.containsKey(keyType)) {
    throw SsiException(
      message: 'toMultikey: $keyType not supported',
      code: SsiExceptionType.invalidKeyType.code,
    );
  }
  final indicator = keyIndicators[keyType]!;
  return Uint8List.fromList([...indicator.indicator, ...pubKeyBytes]);
}

/// The value 256 as a [BigInt].
final b256 = BigInt.from(256);

/// Encodes a [BigInt] to a [Uint8List].
Uint8List encodeBigInt(BigInt number) {
  // see https://github.com/dart-lang/sdk/issues/32803
  // Not handling negative numbers. Decide how you want to do that.
  var bytes = (number.bitLength + 7) >> 3;

  final result = Uint8List(bytes);
  for (var i = 0; i < bytes; i++) {
    result[bytes - 1 - i] = number.remainder(b256).toInt();
    number = number >> 8;
  }

  return result;
}

/// Decodes a [Uint8List] to a [BigInt].
BigInt decodeBigInt(Uint8List bytes) {
  // see https://github.com/dart-lang/sdk/issues/32803
  var result = BigInt.zero;

  for (final byte in bytes) {
    // reading in big-endian, so we essentially concat the new byte to the end
    result = (result << 8) | BigInt.from(byte & 0xff);
  }

  return result;
}
