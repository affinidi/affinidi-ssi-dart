import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:meta/meta.dart';

import 'wallet.dart';
import '../key_pair/secp256k1_key_pair.dart';
import '../types.dart';

class Bip32Wallet implements Wallet {
  static const baseDerivationPath = "m/44'/60'/0'/0/0";
  static const rootKeyId = "0-0";

  final Map<String, Secp256k1KeyPair> _keyMap;

  Bip32Wallet._(this._keyMap);

  factory Bip32Wallet.fromSeed(Uint8List seed) {
    final rootNode = BIP32.fromSeed(seed);
    final rootKeyPair = Secp256k1KeyPair(node: rootNode, keyId: rootKeyId);
    Map<String, Secp256k1KeyPair> keyMap = {rootKeyId: rootKeyPair};
    return Bip32Wallet._(keyMap);
  }

  factory Bip32Wallet.fromPrivateKey(Uint8List privateKey) {
    // TODO: validate if chainCode is correct
    final chainCode = Uint8List(0);
    final rootNode = BIP32.fromPrivateKey(privateKey, chainCode);
    final rootKeyPair = Secp256k1KeyPair(node: rootNode, keyId: rootKeyId);
    Map<String, Secp256k1KeyPair> keyMap = {rootKeyId: rootKeyPair};
    return Bip32Wallet._(keyMap);
  }

  @visibleForTesting
  factory Bip32Wallet.fromBip32Node(BIP32 node) {
    final rootKeyPair = Secp256k1KeyPair(node: node, keyId: rootKeyId);
    Map<String, Secp256k1KeyPair> keyMap = {rootKeyId: rootKeyPair};
    return Bip32Wallet._(keyMap);
  }

  // TODO: recover from key map
  // factory Bip32Wallet.fromKeyMap(Map<String, String> backup) {
  //   if (!backup.containsKey(rootKeyId)) {
  //     throw Exception("Root key doesn't exists in provided backup key map");
  //   }
  // }

  @override
  Future<bool> hasKey(String keyId) {
    return Future.value(_keyMap.containsKey(keyId));
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
  }) {
    final keyPair = _getKeyPair(keyId);
    return keyPair.sign(data, signatureScheme: SignatureScheme.es256k);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
  }) {
    final keyPair = _getKeyPair(keyId);
    return keyPair.verify(data,
        signature: signature, signatureScheme: SignatureScheme.es256k);
  }

  @override
  Future<Secp256k1KeyPair> createKeyPair(String keyId, {KeyType? keyType}) {
    if (keyType != null && keyType != KeyType.secp256k1) {
      throw ArgumentError(
          "Only secp256k1 key type is supported for Bip32Wallet");
    }
    if (_keyMap.containsKey(keyId)) {
      return Future.value(_keyMap[keyId]);
    }
    if (!_keyMap.containsKey(rootKeyId)) {
      throw Exception('Root key pair is missing');
    }
    var (accountNumber, accountKeyId) = _validateKeyId(keyId);

    final derivationPath =
        _buildDerivationPath(baseDerivationPath, accountNumber, accountKeyId);
    var rootNode = _keyMap[rootKeyId]!.getBip32Node();
    var node = Secp256k1KeyPair(
        node: rootNode.derivePath(derivationPath), keyId: keyId);
    _keyMap[keyId] = node;

    return Future.value(node);
  }

  @override
  Future<Uint8List> getPublicKey(String keyId) {
    final keyPair = _getKeyPair(keyId);
    return keyPair.getPublicKey();
  }

  @override
  Future<Secp256k1KeyPair> getKeyPair(String keyId) async {
    return Future.value(_getKeyPair(keyId));
  }

  Secp256k1KeyPair _getKeyPair(String keyId) {
    if (_keyMap.containsKey(keyId)) {
      return _keyMap[keyId]!;
    } else {
      throw ArgumentError('Invalid Key ID: $keyId');
    }
  }

  static (int, int) _validateKeyId(String keyId) {
    // NOTE: agree on approach for multikey support
    // option 1: keyId is composed as `{accountNumber}-{accountKeyId}`
    // option 2: separate the identifiers and require both
    // option 3: use the full derivation path as keyId
    var accountNumber = 0;
    var accountKeyId = 0;
    try {
      List<String> parts = keyId.split("-");
      accountNumber = int.parse(parts[0]);
      accountKeyId = int.parse(parts[1]);
    } catch (e) {
      throw FormatException(
          "For Bip32Wallet the keyId is composed as {accountNumber}-{accountKeyId}, where both accountNumber and accountKeyId are positive integers");
    }
    return (accountNumber, accountKeyId);
  }

  static String _buildDerivationPath(
      String baseDerivationPath, int accountNumber, int accountKeyId) {
    List<String> parts = baseDerivationPath.split('/');
    parts[3] = "$accountNumber'";
    parts[5] = "$accountKeyId";
    return parts.join('/');
  }
}
