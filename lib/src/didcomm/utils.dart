import 'dart:convert';
import 'dart:typed_data';

import 'package:elliptic/elliptic.dart' as ec;
import 'package:ssi/src/did/did_key.dart';
import 'package:ssi/src/key_pair/public_key.dart';
import 'package:ssi/src/types.dart';
import 'package:ssi/src/wallet/bip32_ed25519_wallet.dart';
import 'package:ssi/ssi.dart';
import 'package:web3dart/crypto.dart';
import 'package:x25519/x25519.dart' as x25519;

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

String getCurveByPublicKey(PublicKey publickey) {
  if (publickey.type == KeyType.p256) {
    return 'P-256';
  } else if (publickey.type == KeyType.secp256k1) {
    return 'secp256k1';
  } else if (publickey.type == KeyType.ed25519) {
    return 'X25519';
  }
  throw Exception('curve for public key not implemented');
}

ec.Curve getEllipticCurveByPublicKey(PublicKey publickey) {
  if (publickey.type == KeyType.p256) {
    return ec.getP256();
  } else if (publickey.type == KeyType.secp256k1) {
    return ec.getSecp256k1();
  }
  throw Exception('curve for public key not implemented');
}

ec.Curve getCurveByJwk(publicKeyJwk) {
  if (publicKeyJwk['crv'] == 'P-256') {
    return ec.getP256();
  } else if (publicKeyJwk['crv'] == 'P-384') {
    return ec.getP384();
  } else if (publicKeyJwk['crv'] == 'P-521') {
    return ec.getP521();
  } else if (publicKeyJwk['crv'] == 'secp256k1') {
    return ec.getSecp256k1();
  } else {
    throw UnimplementedError("Curve `${publicKeyJwk['crv']}` not supported");
  }
}

ec.PublicKey publicKeyFromPoint({
  required ec.Curve curve,
  required String x,
  required String y,
}) {
  return ec.PublicKey.fromPoint(
      curve,
      ec.AffinePoint.fromXY(bytesToUnsignedInt(decodeBase64(x)),
          bytesToUnsignedInt(decodeBase64(y))));
}

Uint8List publicKeyBytesFromJwk(Map<String, dynamic> jwk) {
  if (isSecp256OrPCurve(jwk['crv']!)) {
    final publicKey = publicKeyFromPoint(
        curve: getCurveByJwk(jwk), x: jwk['x']!, y: jwk['y']!);
    return hexToBytes(publicKey.toCompressedHex());
  } else if (isXCurve(jwk['crv']!)) {
    return decodeBase64(jwk['x']!);
  }
  throw Exception('JWK to public key bytes convertion not supported');
}

ec.PrivateKey getPrivateKeyFromBytes(
  Uint8List bytes, {
  required KeyType keyType,
}) {
  if (keyType == KeyType.p256) {
    return ec.PrivateKey.fromBytes(ec.getP256(), bytes);
  }

  if (keyType == KeyType.secp256k1) {
    return ec.PrivateKey.fromBytes(ec.getSecp256k1(), bytes);
  }

  throw Exception('Can\'t convert bytes for key type ${keyType.name}');
}

Uint8List getPrivateKeyFromJwk(Map privateKeyJwk, Map epkHeader) {
  final crv = privateKeyJwk['crv'];

  if (crv.startsWith('P') || crv.startsWith('secp256k1')) {
    ec.Curve? c;
    if (crv == 'P-256') {
      c = ec.getP256();
    } else if (crv == 'P-384') {
      c = ec.getP384();
    } else if (crv == 'P-521') {
      c = ec.getP521();
    } else if (crv == 'secp256k1') {
      c = ec.getSecp256k1();
    } else {
      throw UnimplementedError("Curve `$crv` not supported");
    }

    final receiverPrivate =
        ec.PrivateKey(c, bytesToUnsignedInt(decodeBase64(privateKeyJwk['d'])));
    return Uint8List.fromList(receiverPrivate.bytes);
  } else if (crv.startsWith('X')) {
    return decodeBase64(privateKeyJwk['d']);
  } else {
    throw UnimplementedError("Curve `$crv` not supported");
  }
}

({Uint8List privateKeyBytes, Uint8List? publicKeyBytes}) getEphemeralPrivateKey(
  PublicKey publicKey,
) {
  if (publicKey.type == KeyType.p256) {
    return (
      privateKeyBytes:
          Uint8List.fromList(ec.getP256().generatePrivateKey().bytes),
      publicKeyBytes: null
    );
  }

  if (publicKey.type == KeyType.secp256k1) {
    return (
      privateKeyBytes:
          Uint8List.fromList(ec.getSecp256k1().generatePrivateKey().bytes),
      publicKeyBytes: null
    );
  }

  if (publicKey.type == KeyType.ed25519) {
    var eKeyPair = x25519.generateKeyPair();
    return (
      privateKeyBytes: Uint8List.fromList(eKeyPair.privateKey),
      publicKeyBytes: Uint8List.fromList(eKeyPair.publicKey),
    );
  }

  throw Exception('Key type not supported');
}

Future<DidDocument> getDidDocumentForX25519Key(
    Bip32Ed25519Wallet wallet, String keyId) async {
  final x25519PublicKey = await wallet.getX25519PublicKey(keyId);
  return DidKey.generateDocument(
      PublicKey(keyId, x25519PublicKey, KeyType.x25519));
}

bool isSecp256OrPCurve(String crv) {
  return crv.startsWith('P') || crv.startsWith('secp256k');
}

bool isXCurve(String crv) {
  return crv.startsWith('X');
}

String decodeBase64ToString(String data) {
  return utf8.decode(decodeBase64(data));
}

String encodeBase64(Uint8List data) {
  return removePaddingFromBase64(base64UrlEncode(data));
}

Uint8List decodeBase64(String data) {
  return base64Decode(addPaddingToBase64(data));
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
