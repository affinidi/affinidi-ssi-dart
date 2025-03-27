import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';

import '../key_pair/key_pair.dart';
import '../types.dart';
import 'did.dart';

class DidKey implements Did {
  final String _did;
  DidKey(this._did);

  static Future<DidKey> create(KeyPair keyPair) async {
    final keyType = await keyPair.getKeyType();
    final publicKey = await keyPair.getPublicKey();
    final multicodec = _didKeyMulticodes[keyType]!;
    final did = '$commonDidKeyPrefix${base58BitcoinEncode(Uint8List.fromList([
          ...multicodec,
          ...publicKey
        ]))}';
    return DidKey(did);
  }

  static const commonDidKeyPrefix = 'did:key:z';
  static const Map<KeyType, String> _didKeyPrefixes = {
    KeyType.secp256k1: '${commonDidKeyPrefix}Q3s',
    KeyType.ed25519: '${commonDidKeyPrefix}6Mk',
  };

  // TODO: validate multicode of ed25519
  static const Map<KeyType, List<int>> _didKeyMulticodes = {
    KeyType.secp256k1: [231, 1],
    KeyType.ed25519: [237, 1],
  };

  @override
  Future<String> getDid() {
    return Future.value(_did);
  }

  @override
  Future<String> getDidWithKeyId() {
    return Future.value("$_did#${_did.substring("did:key:".length)}");
  }

  @override
  Future<Uint8List> getPublicKey() {
    final keyType = _didKeyPrefixes.entries
        .where((e) => _did.startsWith(e.value))
        .map((e) => e.key)
        .firstOrNull;

    if (keyType == null) {
      throw FormatException('Unsupported DID key format');
    }

    final multicode = _didKeyMulticodes[keyType]!;
    final bytes = base58BitcoinDecode(
      _did.substring(commonDidKeyPrefix.length),
    );
    return Future.value(bytes.sublist(multicode.length));
  }

  @override
  String toString() {
    return _did;
  }
}
