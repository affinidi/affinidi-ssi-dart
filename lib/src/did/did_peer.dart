import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';

import '../key_pair/key_pair.dart';
import '../types.dart';
import 'did.dart';

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
