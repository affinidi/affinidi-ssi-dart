import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';

import '../credentials/exceptions/ssi_exception.dart';
import '../credentials/exceptions/ssi_exception_type.dart';
import '../key_pair/key_pair.dart';
import '../types.dart';
import '../utility.dart';
import 'did_document.dart';

Future<DidDocument> _buildEDDoc(
  List<String> context,
  String id,
  String keyPart,
) {
  var multiCodecXKey = ed25519PublicToX25519Public(
    base58Bitcoin.decode(keyPart).sublist(2),
  );
  if (!multiCodecXKey.startsWith('6LS')) {
    throw SsiException(
      message:
          'Something went wrong during conversion from Ed25515 to curve25519 key',
      code: SsiExceptionType.invalidDidKey.code,
    );
  }
  String verificationKeyId = '$id#z$keyPart';
  String agreementKeyId = '$id#z$multiCodecXKey';

  var verification = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: base58Bitcoin.decode(keyPart),
  );
  var keyAgreement = VerificationMethodMultibase(
    id: agreementKeyId,
    controller: id,
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: base58Bitcoin.decode(multiCodecXKey),
  );

  return Future.value(
    DidDocument(
        context: context,
        id: id,
        verificationMethod: [verification, keyAgreement],
        assertionMethod: [verificationKeyId],
        keyAgreement: [agreementKeyId],
        authentication: [verificationKeyId],
        capabilityDelegation: [verificationKeyId],
        capabilityInvocation: [verificationKeyId]),
  );
}

Future<DidDocument> _buildXDoc(
  List<String> context,
  String id,
  String keyPart,
) {
  String verificationKeyId = '$id#z$keyPart';
  var verification = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: base58Bitcoin.decode(keyPart),
  );
  return Future.value(
    DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification],
      keyAgreement: [verificationKeyId],
    ),
  );
}

Future<DidDocument> _buildOtherDoc(
  List<String> context,
  String id,
  String keyPart,
  String type,
) {
  String verificationKeyId = '$id#z$keyPart';
  var verification = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: type,
    publicKeyMultibase: base58Bitcoin.decode(keyPart),
  );
  return Future.value(
    DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification],
      assertionMethod: [verificationKeyId],
      authentication: [verificationKeyId],
      capabilityDelegation: [verificationKeyId],
      capabilityInvocation: [verificationKeyId],
      keyAgreement: [verificationKeyId],
    ),
  );
}

class DidKey {
  static Future<DidDocument> create(List<KeyPair> keyPairs) async {
    var keyPair = keyPairs[0];
    final keyType = await keyPair.getKeyType();
    final publicKey = await keyPair.getPublicKey();
    final multicodec = _didKeyMulticodes[keyType]!;
    final multibase = base58BitcoinEncode(
      Uint8List.fromList([...multicodec, ...publicKey]),
    );
    final did = '$commonDidKeyPrefix$multibase';
    final keyId = '$did#$multibase';

    // FIXME double check the doc
    return DidDocument(
      id: did,
      verificationMethod: [
        VerificationMethodMultibase(
          id: did,
          controller: keyId,
          type: 'Multikey',
          publicKeyMultibase: Uint8List.fromList([...multicodec, ...publicKey]),
        )
      ],
      authentication: [keyId],
      assertionMethod: [keyId],
      capabilityInvocation: [keyId],
      capabilityDelegation: [keyId],
    );
  }

  static Future<DidDocument> resolve(String did) {
    if (!did.startsWith('did:key')) {
      throw SsiException(
        message: 'Expected did to start with `did:key`. However `$did` did not',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }
    var splited = did.split(':');
    if (splited.length != 3) {
      throw SsiException(
        message: 'malformed did: `$did`',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }

    String keyPart = splited[2];
    var multibaseIndicator = keyPart[0];
    keyPart = keyPart.substring(1);

    var context = [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
      "https://w3id.org/security/suites/x25519-2020/v1"
    ];

    var context2 = [
      "https://www.w3.org/ns/did/v1",
      'https://ns.did.ai/suites/multikey-2021/v1/'
    ];

    var id = did;

    if (multibaseIndicator != 'z') {
      throw UnimplementedError('Only Base58 is supported yet');
    }

    if (keyPart.startsWith('6Mk')) {
      return _buildEDDoc(context, id, keyPart);
    } else if (keyPart.startsWith('6LS')) {
      return _buildXDoc(context, id, keyPart);
    } else if (keyPart.startsWith('Dn')) {
      return _buildOtherDoc(context2, id, keyPart, 'P256Key2021');
    } else if (keyPart.startsWith('Q3s')) {
      return _buildOtherDoc(context2, id, keyPart, 'Secp256k1Key2021');
    } else if (keyPart.startsWith('82')) {
      return _buildOtherDoc(context2, id, keyPart, 'P384Key2021');
    } else if (keyPart.startsWith('2J9')) {
      return _buildOtherDoc(context2, id, keyPart, 'P521Key2021');
    } else {
      throw UnimplementedError(
          'Only Ed25519 and X25519 keys are supported now');
    }
  }

  static const commonDidKeyPrefix = 'did:key:z';

  // static const Map<KeyType, String> _didKeyPrefixes = {
  //   KeyType.secp256k1: '${commonDidKeyPrefix}Q3s',
  //   KeyType.ed25519: '${commonDidKeyPrefix}6Mk',
  // };

  static const Map<KeyType, List<int>> _didKeyMulticodes = {
    KeyType.secp256k1: [231, 1],
    KeyType.ed25519: [237, 1],
  };
}
