import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';

import '../key_pair/key_pair.dart';
import '../types.dart';
import '../utility.dart';

import 'did.dart';

import 'did_document.dart';

class BaseKey {
  KeyType keyType;
  List<int> pubKeyBytes;
  BaseKey(this.pubKeyBytes, this.keyType);
}

enum Numalgo2Prefix {
  authentication("V"),
  keyAgreement("E"),
  service("S");

  final String value;
  const Numalgo2Prefix(this.value);
}

final RegExp peerDIDPattern = RegExp(
    r'^did:peer:(([0](z)[1-9a-km-zA-HJ-NP-Z]+)|([2](\.[AEVID](z)[1-9a-km-zA-HJ-NP-Z]+)+)+(\.(S)[0-9a-zA-Z]*)?)');

bool isPeerDID(String peerDID) {
  return peerDIDPattern.hasMatch(peerDID);
}

Future<DidDocument> _resolveDidPeer0(String did) {
  var multibaseIndicator = did[10];

  if (multibaseIndicator != 'z') {
    throw UnimplementedError('Only Base58 is supported yet');
  }

  var contextEdward = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ];
  var contextedX = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"
  ];

  String keyPart = did.substring(11);

  if (keyPart.startsWith('6Mk')) {
    return _buildEDDoc(contextEdward, did, keyPart);
  } else if (keyPart.startsWith('6LS')) {
    return _buildXDoc(contextedX, did, keyPart);
    // } else if (keyPart.startsWith('Dn')) {
    //   return _buildOtherDoc(context2, id, keyPart, 'P256Key2021');
    // } else if (keyPart.startsWith('Q3s')) {
    //   return _buildOtherDoc(context2, id, keyPart, 'Secp256k1Key2021');
    // } else if (keyPart.startsWith('82')) {
    //   return _buildOtherDoc(context2, id, keyPart, 'P384Key2021');
    // } else if (keyPart.startsWith('2J9')) {
    //   return _buildOtherDoc(context2, id, keyPart, 'P521Key2021');
  } else {
    throw UnimplementedError('Only Ed25519 and X25519 keys are supported now');
  }
}

Future<DidDocument> _resolveDidPeer2(String did) {
  String keysPart = did.substring(11);

  List<String> authenticationKeys = [];
  List<String> agreementKeys = [];
  String? serviceString;

  var keys = keysPart.split('.');
  for (var key in keys) {
    var prefix = key[0];

    var keyPart = key.substring(1);
    if (prefix == Numalgo2Prefix.service.value) {
      serviceString = key.substring(1);
    } else if (prefix == Numalgo2Prefix.authentication.value) {
      authenticationKeys.add(keyPart);
    } else if (prefix == Numalgo2Prefix.keyAgreement.value) {
      agreementKeys.add(keyPart);
    } else {
      throw UnimplementedError("Unknown prefix: $prefix.");
    }
  }

  return _buildMultiKeysDoc(
      did, agreementKeys, authenticationKeys, serviceString);
}

Future<DidDocument> resolveDidPeer(String did) {
  if (!isPeerDID(did)) {
    throw Exception('`$did` Does not match peer DID regexp.');
  }

  bool isPeer0 = did[9] == '0';
  if (isPeer0) {
    return _resolveDidPeer0(did);
  } else {
    return _resolveDidPeer2(did);
  }
}

Future<DidDocument> _buildMultiKeysDoc(String did, List<String> agreementKeys,
    List<String> authenticationKeys, String? serviceStr) {
  var context = [
    "https://www.w3.org/ns/did/v1",
    'https://ns.did.ai/suites/multikey-2021/v1/'
  ];

  List<VerificationMethod> verificationMethod = [];
  List<dynamic> assertionMethod = [];
  List<dynamic> keyAgreement = [];
  List<dynamic> authentication = [];

  List<ServiceEndpoint>? service;
  if (serviceStr != null) {
    int paddingNeeded = (4 - serviceStr.length % 4) % 4;
    String padded = serviceStr + ('=' * paddingNeeded);

    Uint8List serviceList = base64Decode(padded);
    dynamic serviceJson = json.decode(utf8.decode(serviceList));
    serviceJson['serviceEndpoint'] = serviceJson['s'];
    serviceJson['accept'] = serviceJson['a'];
    serviceJson['type'] = serviceJson['t'];
    if (serviceJson['type'] == 'dm') {
      serviceJson['type'] = 'DIDCommMessaging';
    }
    service = [ServiceEndpoint.fromJson(serviceJson)];
  }

  var i = 0;

  for (var agreementKey in agreementKeys) {
    i++;
    var type = agreementKey.startsWith('z6LS')
        ? 'X25519KeyAgreementKey2020'
        : 'Ed25519VerificationKey2020';

    String kid = '#key-$i';
    var verification = VerificationMethod(
        id: kid,
        controller: did,
        type: type, // Multikey ?
        publicKeyMultibase: agreementKey);

    verificationMethod.add(verification);
    keyAgreement.add(kid);
  }

  for (var authenticationKey in authenticationKeys) {
    i++;
    var type = authenticationKey.startsWith('z6LS')
        ? 'X25519KeyAgreementKey2020'
        : 'Ed25519VerificationKey2020';

    String kid = '#key-$i';
    var verification = VerificationMethod(
        id: kid,
        controller: did,
        type: type, // Multikey ?
        publicKeyMultibase: authenticationKey);

    verificationMethod.add(verification);
    assertionMethod.add(kid);
    authentication.add(kid);
  }

  return Future.value(DidDocument(
      context: context,
      id: did,
      verificationMethod: verificationMethod,
      assertionMethod: assertionMethod,
      keyAgreement: keyAgreement,
      authentication: authentication,
      service: service));
}

Future<DidDocument> _buildEDDoc(
    List<String> context, String id, String keyPart) {
  var multiCodecXKey =
      ed25519PublicToX25519Public(base58Bitcoin.decode(keyPart).sublist(2));
  if (!multiCodecXKey.startsWith('6LS')) {
    throw Exception(
        'Something went wrong during conversion from Ed25515 to curve25519 key');
  }
  String verificationKeyId = '$id#$keyPart';
  String agreementKeyId = '$id#z$multiCodecXKey';

  var verification = VerificationMethod(
      id: verificationKeyId,
      controller: id,
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z$keyPart');
  // var keyAgreement = VerificationMethod(
  //     id: agreementKeyId,
  //     controller: id,
  //     type: 'X25519KeyAgreementKey2020',
  //     publicKeyMultibase: 'z$multiCodecXKey');

  return Future.value(DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification],
      assertionMethod: [verificationKeyId],
      keyAgreement: [agreementKeyId],
      authentication: [verificationKeyId],
      capabilityDelegation: [verificationKeyId],
      capabilityInvocation: [verificationKeyId]));
}

Future<DidDocument> _buildXDoc(
    List<String> context, String id, String keyPart) {
  String verificationKeyId = '$id#z$keyPart';
  var verification = VerificationMethod(
      id: verificationKeyId,
      controller: id,
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase: 'z$keyPart');
  return Future.value(DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification],
      keyAgreement: [verificationKeyId]));
}

class DidPeer implements Did {
  final String _did;
  late DidPeerType _didType;
  DidPeer(did) : _did = did {
    if (_did.startsWith(_didTypePrefixes[DidPeerType.peer0]!)) {
      _didType = DidPeerType.peer0;
    } else {
      _didType = DidPeerType.peer2;
    }
  }

  static String _getDidPeerMultibasePart(
      List<int> pubKeyBytes, KeyType keyType) {
    final multicodec = _keyMulticodes[keyType]!;
    return 'z${base58Bitcoin.encode(Uint8List.fromList([
          ...multicodec,
          ...pubKeyBytes
        ]))}';
  }

  static String _buildServiceEncoded(String? serviceEndpoint) {
    if (serviceEndpoint == null) {
      return '';
    }

    String jsonString = json.encode({
      'id': 'new-id',
      't': 'dm', // "type": "DIDCommMessaging"
      's': serviceEndpoint, // serviceEndpoint
      'a': ['didcomm/v2'], // accept
    });

    return ".${Numalgo2Prefix.service.value}${base64UrlEncode(utf8.encode(jsonString)).replaceAll('=', '')}";
  }

  static String _pubKeysToPeerDid(List<BaseKey> signingKeys,
      [List<BaseKey>? agreementKeys, String? serviceEndpoint]) {
    bool isDid0 = signingKeys.length == 1 &&
        (agreementKeys == null && serviceEndpoint == null);

    if (isDid0) {
      dynamic signingKey = signingKeys[0];
      var multibase =
          _getDidPeerMultibasePart(signingKey.pubKeyBytes, signingKey.keyType);
      return '${_didTypePrefixes[DidPeerType.peer0]}$multibase';
    }

    String encSep = '.${Numalgo2Prefix.keyAgreement.value}';
    String authSep = '.${Numalgo2Prefix.authentication.value}';

    bool isAgreementNotEmpty =
        agreementKeys != null && agreementKeys.isNotEmpty;

    String agreementKeysStr = isAgreementNotEmpty
        ? encSep +
            agreementKeys
                .map((key) =>
                    _getDidPeerMultibasePart(key.pubKeyBytes, key.keyType))
                .join(encSep)
        : '';
    String authKeysStr = signingKeys.isNotEmpty
        ? authSep +
            signingKeys
                .map((key) =>
                    _getDidPeerMultibasePart(key.pubKeyBytes, key.keyType))
                .join(authSep)
        : '';
    String serviceStr = _buildServiceEncoded(serviceEndpoint);

    return '${_didTypePrefixes[DidPeerType.peer2]}$agreementKeysStr$authKeysStr$serviceStr';
  }

  static String _pubKeyToPeerDid(List<BaseKey> baseKeys,
      [String? serviceEndpoint]) {
    // bool isDid0 = keyPairs.length == 1 && serviceEndpoint == null;
    DidPeerType didType = baseKeys.length == 1 && serviceEndpoint == null
        ? DidPeerType.peer0
        : DidPeerType.peer2;

    if (didType != DidPeerType.peer0) {
      return _pubKeysToPeerDid(baseKeys, baseKeys, serviceEndpoint);
    } else {
      return _pubKeysToPeerDid(baseKeys);
    }
  }

  static Future<DidPeer> create(List<KeyPair> keyPairs,
      [String? serviceEndpoint]) async {
    List<BaseKey> baseKeys = [];

    for (var keyPair in keyPairs) {
      final keyType = await keyPair.getKeyType();
      final pubKeyBytes = await keyPair.getPublicKey();
      BaseKey baseKey = BaseKey(pubKeyBytes, keyType);

      baseKeys.add(baseKey);
    }

    final did = _pubKeyToPeerDid(baseKeys, serviceEndpoint);
    return DidPeer(did);
  }

  static Future<DidDocument> resolve(String did) {
    if (!isPeerDID(did)) {
      throw Exception('`$did` Does not match peer DID regexp.');
    }

    bool isPeer0 = did[9] == '0';
    if (isPeer0) {
      return _resolveDidPeer0(did);
    } else {
      return _resolveDidPeer2(did);
    }
  }

  static const Map<KeyType, String> _keyTypePrefixes = {
    KeyType.x25519: '6LS',
    KeyType.ed25519: '6Mk',
  };

  static const Map<KeyType, List<int>> _keyMulticodes = {
    KeyType.x25519: [236, 1],
    KeyType.ed25519: [237, 1],
  };

  static const Map<DidPeerType, String> _didTypePrefixes = {
    DidPeerType.peer0: 'did:peer:0',
    DidPeerType.peer2: 'did:peer:2',
  };

  String _getFirstMultiBaseSigninKey(String did) {
    if (_didType == DidPeerType.peer0) {
      return did.substring("did:peer:0z".length);
    } else {
      String keysPart = did.substring(11);
      var keys = keysPart.split('.');
      List<String> signinKeys = [];

      for (var key in keys) {
        var prefix = key[0];
        var keyPart = key.substring(1);
        if (prefix == Numalgo2Prefix.authentication.value) {
          signinKeys.add(keyPart);
        }
      }

      return signinKeys[0].substring(1);
    }
  }

  @override
  Future<String> getDid() {
    return Future.value(_did);
  }

  @override
  Future<String> getDidWithKeyId() {
    String multiBaseKey = _getFirstMultiBaseSigninKey(_did);
    return Future.value("$_did#$multiBaseKey");
  }

  @override
  Future<Uint8List> getPublicKey() {
    String multiBaseKey = _getFirstMultiBaseSigninKey(_did);

    final keyType = _keyTypePrefixes.entries
        .where((e) => multiBaseKey.startsWith(e.value))
        .map((e) => e.key)
        .firstOrNull;

    if (keyType == null) {
      throw FormatException('Unsupported DID key format');
    }

    final multicode = _keyMulticodes[keyType]!;
    final bytes = base58BitcoinDecode(multiBaseKey);

    return Future.value(bytes.sublist(multicode.length));
  }

  @override
  String toString() {
    return _did;
  }
}
