import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_multihash/dart_multihash.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:ssi/src/key_pair/public_key.dart';
import 'package:ssi/src/types.dart';
import 'package:web3dart/crypto.dart';

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

bool checkMultiHash(Uint8List hash, Uint8List data) {
  var multihash = Multihash.decode(hash);
  if (multihash.code != 0x12) {
    throw Exception("Hash function must be "
        "sha2-256 for now (Code: 34893)");
  }

  var hashedData = sha256.convert(data).bytes;
  for (var i = 0; i < hashedData.length; i++) {
    var a = multihash.digest[i];
    var b = hashedData[i];
    if (a != b) {
      return false;
    }
  }
  return hashedData.length == multihash.digest.length;
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

elliptic.Curve getEllipticCurveByPublicKey(PublicKey publickey) {
  if (publickey.type == KeyType.p256) {
    return elliptic.getP256();
  } else if (publickey.type == KeyType.secp256k1) {
    return elliptic.getSecp256k1();
  }
  throw Exception('curve for public key not implemented');
}

elliptic.Curve getCurveByJwk(publicKeyJwk) {
  if (publicKeyJwk['crv'] == 'P-256') {
    return elliptic.getP256();
  } else if (publicKeyJwk['crv'] == 'P-384') {
    return elliptic.getP384();
  } else if (publicKeyJwk['crv'] == 'P-521') {
    return elliptic.getP521();
  } else if (publicKeyJwk['crv'] == 'secp256k1') {
    return elliptic.getSecp256k1();
  } else {
    throw UnimplementedError("Curve `${publicKeyJwk['crv']}` not supported");
  }
}

elliptic.PublicKey publicKeyFromPoint({
  required elliptic.Curve curve,
  required String x,
  required String y,
}) {
  return elliptic.PublicKey.fromPoint(
      curve,
      elliptic.AffinePoint.fromXY(
          bytesToUnsignedInt(base64Decode(addPaddingToBase64(x))),
          bytesToUnsignedInt(base64Decode(addPaddingToBase64(y)))));
}

elliptic.PrivateKey getPrivateKeyFromBytes(
  Uint8List bytes, {
  required KeyType keyType,
}) {
  if (keyType == KeyType.p256) {
    return elliptic.PrivateKey.fromBytes(elliptic.getP256(), bytes);
  }

  if (keyType == KeyType.secp256k1) {
    return elliptic.PrivateKey.fromBytes(elliptic.getSecp256k1(), bytes);
  }

  throw Exception('Can\'t convert bytes for key type ${keyType.name}');
}

elliptic.PrivateKey getPrivateKeyFromJwk(Map privateKeyJwk, Map epkHeader) {
  var crv = privateKeyJwk['crv'];

  elliptic.Curve? c;
  dynamic receiverPrivate, epkPublic;

  if (crv.startsWith('P') || crv.startsWith('secp256k1')) {
    if (crv == 'P-256') {
      c = elliptic.getP256();
    } else if (crv == 'P-384') {
      c = elliptic.getP384();
    } else if (crv == 'P-521') {
      c = elliptic.getP521();
    } else if (crv == 'secp256k1') {
      c = elliptic.getSecp256k1();
    } else {
      throw UnimplementedError("Curve `$crv` not supported");
    }

    receiverPrivate = elliptic.PrivateKey(
        c,
        bytesToUnsignedInt(
            base64Decode(addPaddingToBase64(privateKeyJwk['d']))));
    epkPublic = elliptic.PublicKey.fromPoint(
        c,
        elliptic.AffinePoint.fromXY(
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(epkHeader!['x']))),
            bytesToUnsignedInt(
                base64Decode(addPaddingToBase64(epkHeader!['y'])))));
  } else if (crv.startsWith('X')) {
    receiverPrivate = base64Decode(addPaddingToBase64(privateKeyJwk['d']));
    epkPublic = base64Decode(addPaddingToBase64(epkHeader!['x']));
  } else {
    throw UnimplementedError("Curve `$crv` not supported");
  }

  return receiverPrivate;
}

bool isSecp256OrPCurve(String crv) {
  return crv.startsWith('P') || crv.startsWith('secp256k');
}

/// Signs the given String (normal or Json-Object) or Json-Object (Dart Map<String, dynamic>) [toSign] with key-pair of [didToSignWith].
///
/// Returned signature is formatted as jws. If a detached jws (header..signature) should be returned [detached] must be set to true.
/// If no custom [jwsHeader] is given, the default one is
/// ```
/// {
///   "alg" : "ES256K-R",
///   "b64" : false,
///   "crit" : ["b64"]
/// }
/// ```
/// if did is of type did:ethr or
/// ```
/// {
///   "alg" : "EdDSA",
///   "crv" : "Ed25519"
/// }
/// ```
/// if did is of type did:key with appropriate key-Material
/// If a custom one should be used, it has to be given in its json representation (dart String or Map) and the value of alg has to be ES256K-R or EdDSA with curve Ed25519,
/// because for now this is the only supported signature algorithm.
// Future<String> signStringOrJson(
//     {WalletStore? wallet,
//     String? didToSignWith,
//     Map<String, dynamic>? jwk,
//     required dynamic toSign,
//     Signer? signer,
//     bool detached = false,
//     dynamic jwsHeader}) async {
//   signer ??= jwk != null
//       ? _determineSignerForJwk(jwk, null)
//       : jwsHeader != null
//           ? _determineSignerForJwsHeader(jwsHeader, loadDocument)
//           : _determineSignerForDid(didToSignWith!, null);
//   return signer.sign(
//       data: toSign,
//       wallet: wallet,
//       did: didToSignWith,
//       jwk: jwk,
//       detached: detached,
//       jwsHeader: jwsHeader);
// }

/// Verifies the signature in [jws].
///
/// If a detached jws is given the signed string must be given separately as [toSign].
/// [toSign] could be a String or a json-object (Dart Map).
// Future<bool> verifyStringSignature(String jws,
//     {String? expectedDid,
//     Map<String, dynamic>? jwk,
//     dynamic toSign,
//     Erc1056? erc1056}) async {
//   var signer = _determineSignerForJwsHeader(jws.split('.').first, null);
//   if (expectedDid != null &&
//       expectedDid.startsWith('did:ethr') &&
//       erc1056 != null) {
//     expectedDid = await erc1056.identityOwner(expectedDid);
//   }

//   return signer.verify(jws, did: expectedDid, jwk: jwk, data: toSign);
// }

// Signer _determineSignerForJwsHeader(dynamic jwsHeader,
//     Function(Uri url, LoadDocumentOptions? options)? loadDocumentFunction) {
//   var header = jwsHeader is Map
//       ? jwsHeader
//       : jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(jwsHeader))));
//   var alg = header['alg'];
//   if (alg == 'EdDSA') {
//     return EdDsaSigner(loadDocumentFunction);
//   } else if (alg == 'ES256K-R') {
//     return EcdsaRecoverySignature(loadDocumentFunction);
//   } else if (alg == 'ES256') {
//     return Es256Signer();
//   } else if (alg == 'ES256K') {
//     return Es256k1Signer();
//   } else {
//     throw Exception('could not examine signature type');
//   }
// }

// List<int> ecdhES(dynamic privateKey, dynamic publicKey, String alg, String enc,
//     {String? apu, String? apv}) {
//   List<int> z;
//   if (privateKey is elliptic.PrivateKey && publicKey is elliptic.PublicKey) {
//     z = ecdh.computeSecret(privateKey, publicKey);
//   } else if (privateKey is List<int> && publicKey is List<int>) {
//     z = x25519.X25519(privateKey, publicKey);
//   } else if (publicKey is Map && privateKey is Map) {
//     // keys given as jwks
//     var crv = privateKey['crv'];
//     if (crv != publicKey['crv']) {
//       throw Exception('curves do not match ($crv != ${publicKey['crv']}');
//     }
//     elliptic.Curve? c;

//     if (crv.startsWith('P') || crv.startsWith('secp256k1')) {
//       if (crv == 'P-256') {
//         c = elliptic.getP256();
//       } else if (crv == 'P-384') {
//         c = elliptic.getP384();
//       } else if (crv == 'P-521') {
//         c = elliptic.getP521();
//       } else if (crv == 'secp256k1') {
//         c = elliptic.getSecp256k1();
//       } else {
//         throw UnimplementedError("Curve `$crv` not supported");
//       }

//       var castedPrivate = elliptic.PrivateKey(
//           c,
//           bytesToUnsignedInt(
//               base64Decode(addPaddingToBase64(privateKey['d']))));
//       var castedPublic = elliptic.PublicKey.fromPoint(
//           c,
//           elliptic.AffinePoint.fromXY(
//               bytesToUnsignedInt(
//                   base64Decode(addPaddingToBase64(publicKey['x']))),
//               bytesToUnsignedInt(
//                   base64Decode(addPaddingToBase64(publicKey['y'])))));
//       z = ecdh.computeSecret(castedPrivate, castedPublic);
//     } else if (crv.startsWith('X')) {
//       var castedPrivate = base64Decode(addPaddingToBase64(privateKey['d']));
//       var castedPublic = base64Decode(addPaddingToBase64(publicKey['x']));
//       z = x25519.X25519(castedPrivate, castedPublic);
//     } else {
//       throw UnimplementedError("Curve `$crv` not supported");
//     }
//   } else {
//     throw Exception('Unknown key-Type');
//   }

//   var keyDataLen = 128;
//   Uint8List encAscii;
//   if (alg == 'ECDH-ES') {
//     encAscii = ascii.encode(enc);
//     if (enc.contains('128')) {
//       keyDataLen = 128;
//     }
//     if (enc.contains('192')) {
//       keyDataLen = 192;
//     }
//     if (enc.contains('256')) {
//       keyDataLen = 256;
//     }
//   } else {
//     // with KeyWrap
//     encAscii = ascii.encode(alg);
//     if (alg.contains('128')) {
//       keyDataLen = 128;
//     }
//     if (alg.contains('192')) {
//       keyDataLen = 192;
//     }
//     if (alg.contains('256')) {
//       keyDataLen = 256;
//     }
//   }
//   print('enc: $enc, alg: $alg, len: $keyDataLen');
//   var suppPubInfo = _int32BigEndianBytes(keyDataLen);

//   var encLength = _int32BigEndianBytes(encAscii.length);

//   List<int> partyU, partyULength;
//   if (apu != null) {
//     partyU = base64Decode(addPaddingToBase64(apu));
//     partyULength = _int32BigEndianBytes(partyU.length);
//   } else {
//     partyU = [];
//     partyULength = _int32BigEndianBytes(0);
//   }

//   List<int> partyV, partyVLength;
//   if (apv != null) {
//     partyV = base64Decode(addPaddingToBase64(apv));
//     partyVLength = _int32BigEndianBytes(partyV.length);
//   } else {
//     partyV = [];
//     partyVLength = _int32BigEndianBytes(0);
//   }

//   var otherInfo = encLength +
//       encAscii +
//       partyULength +
//       partyU +
//       partyVLength +
//       partyV +
//       suppPubInfo;

//   var kdfIn = [0, 0, 0, 1] + z + otherInfo;
//   var digest = sha256.convert(kdfIn);
//   return digest.bytes.sublist(0, keyDataLen ~/ 8);
// }

Uint8List _int32BigEndianBytes(int value) =>
    Uint8List(4)..buffer.asByteData().setInt32(0, value, Endian.big);
