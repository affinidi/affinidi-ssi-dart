import 'dart:convert';
import 'dart:typed_data';
import 'package:ssi/src/did/did_document.dart';
import 'package:ssi/src/did/did_signer.dart';
import 'package:ssi/src/did/did_verifier.dart';
import 'package:ssi/src/didcomm/message/didcomm_encrypted_message.dart';
import 'package:ssi/src/didcomm/message/didcomm_message.dart';
import 'package:ssi/src/didcomm/message/didcomm_plaintext_message.dart';
import 'package:ssi/src/didcomm/message/jws_header.dart';
import 'package:ssi/src/didcomm/signature_object.dart';
import 'package:ssi/src/didcomm/types.dart';
import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/types.dart';
import 'package:ssi/src/wallet/wallet.dart';

class DidcommSignedMessage implements JsonObject, DidcommMessage {
  late DidcommMessage payload;
  List<SignatureObject>? signatures;
  String? _base64Payload;

  DidcommSignedMessage({required this.payload, this.signatures});

  DidcommSignedMessage.fromJson(dynamic jsonObject) {
    var sig = credentialToMap(jsonObject);
    if (sig.containsKey('payload')) {
      _base64Payload = sig['payload'];
      var decodedPayload =
          utf8.decode(base64Decode(addPaddingToBase64(sig['payload'])));
      try {
        payload = DidcommSignedMessage.fromJson(decodedPayload);
      } catch (e) {
        try {
          payload = DidcommPlaintextMessage.fromJson(decodedPayload);
        } catch (e) {
          try {
            payload = DidcommEncryptedMessage.fromJson(decodedPayload);
          } catch (e) {
            throw Exception('Unknown message type');
          }
        }
      }
    } else {
      throw Exception('payload is needed in jws');
    }
    if (sig.containsKey('signatures')) {
      List tmp = sig['signatures'];
      if (tmp.isNotEmpty) {
        signatures = [];
        for (var s in tmp) {
          signatures!.add(SignatureObject.fromJson(s));
        }
      } else {
        throw Exception('Empty Signatures');
      }
    } else {
      throw Exception('signature property is needed in jws');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['payload'] = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(payload.toString())));

    if (signatures != null) {
      List sigs = [];
      for (var s in signatures!) {
        sigs.add(s.toJson());
      }
      jsonObject['signatures'] = sigs;
    }

    return jsonObject;
  }

  static Future<DidcommSignedMessage> fromPlaintext(
      DidcommPlaintextMessage message,
      {required DidSigner signer}) async {
    message.from ??= signer.did;
    DidcommSignedMessage signedMessage = DidcommSignedMessage(payload: message);
    return signedMessage.sign(signer);
  }

  Future<DidcommEncryptedMessage> encrypt({
    KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.ecdh1PU,
    EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.a256cbc,
    required Wallet wallet,
    required String keyId,
    required List<Map<String, dynamic>> recipientPublicKeyJwks,
  }) {
    return DidcommEncryptedMessage.fromPlaintext(
        keyWrapAlgorithm: keyWrapAlgorithm,
        encryptionAlgorithm: encryptionAlgorithm,
        wallet: wallet,
        keyId: keyId,
        recipientPublicKeyJwks: recipientPublicKeyJwks,
        message: this);
  }

  Future<DidcommSignedMessage> sign(DidSigner signer) async {
    signatures ??= [];

    JwsHeader jwsHeader = JwsHeader(
        typ: DidcommMessageTyp.signed.value,
        alg: signer.signatureScheme.alg!,
        crv: signer.signatureScheme.crv!);

    String data = _base64Payload != null
        ? utf8.decode(base64Decode(_base64Payload!))
        : jsonEncode(payload.toJson());

    String encodedHeader = removePaddingFromBase64(
        base64UrlEncode(utf8.encode(jsonEncode(jwsHeader.toJson()))));

    String encodedPayload =
        removePaddingFromBase64(base64UrlEncode(utf8.encode(data)));

    Uint8List signingInput = ascii.encode('$encodedHeader.$encodedPayload');
    Uint8List jws = await signer.sign(signingInput);

    final sig = removePaddingFromBase64(base64UrlEncode(jws));
    final result = '$encodedHeader..$sig';

    signatures!.add(SignatureObject(
        signature: result.split('..').last,
        protected: jwsHeader.toJson(),
        header: {'kid': signer.keyId}));

    return this;
  }

  Future<bool> verifyUsingJwk(Jwk jwk) async {
    if (jwk.doc['crv'] == null) {
      throw Exception('Jwk without crv parameter');
    }

    if (signatures == null || signatures!.isEmpty) {
      throw Exception('Nothing to verify');
    }

    bool valid = true;

    for (var s in signatures!) {
      var encodedHeader = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(s.protected))));

      var encodedPayload = _base64Payload ??
          removePaddingFromBase64(
              base64UrlEncode(utf8.encode(payload.toString())));

      SignatureScheme sigScheme =
          SignatureScheme.fromString(s.protected!['alg']);

      final verifier = await DidVerifier.create(
        algorithm: sigScheme,
        issuerDid: jwk.toJson()['kid']!.split('#').first,
      );

      valid = verifier.verify(ascii.encode('$encodedHeader.$encodedPayload'),
          base64Decode(addPaddingToBase64(s.signature)));

      if (!valid) {
        throw Exception('A Signature is wrong');
      }
    }

    return valid;
  }

  Future<bool> verify(DidVerifier verifier) async {
    if (signatures == null || signatures!.isEmpty) {
      throw Exception('Nothing to verify');
    }

    bool valid = true;

    for (var s in signatures!) {
      var encodedHeader = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(s.protected))));

      var encodedPayload = _base64Payload ??
          removePaddingFromBase64(
              base64UrlEncode(utf8.encode(payload.toString())));

      valid = verifier.verify(ascii.encode('$encodedHeader.$encodedPayload'),
          base64Decode(addPaddingToBase64(s.signature)));

      if (!valid) {
        throw Exception('A Signature is wrong');
      }
    }

    return valid;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
