import 'dart:typed_data';

import 'package:ed25519_hd_key/ed25519_hd_key.dart';
// import 'package:meta/meta.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import 'wallet.dart';
import '../key_pair/ed25519_key_pair.dart';
import '../types.dart';

class Bip32Ed25519Wallet implements Wallet {
  static const baseDerivationPath = "m/44'/60'/0'/0'/0'";
  static const rootKeyId = "0-0";

  final Map<String, Ed25519KeyPair> _keyMap;

  Bip32Ed25519Wallet._(this._keyMap);

  static Future<Bip32Ed25519Wallet> fromSeed(Uint8List seed) async {
    KeyData master = await ED25519_HD_KEY.getMasterKeyFromSeed(seed);
    var privateKey = ed.newKeyFromSeed(Uint8List.fromList(master.key));
    final rootKeyPair =
        Ed25519KeyPair(privateKey: privateKey, keyId: rootKeyId);
    Map<String, Ed25519KeyPair> keyMap = {rootKeyId: rootKeyPair};
    return Bip32Ed25519Wallet._(keyMap);
  }

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
    return keyPair.sign(data, signatureScheme: SignatureScheme.ed25519sha256);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
  }) {
    final keyPair = _getKeyPair(keyId);
    return keyPair.verify(data,
        signature: signature, signatureScheme: SignatureScheme.ed25519sha256);
  }

  @override
  Future<Ed25519KeyPair> createKeyPair(String keyId, {KeyType? keyType}) async {
    if (keyType != null && keyType != KeyType.ed25519) {
      throw ArgumentError(
          "Only ed25519 key type is supported for Bip32Ed25519Wallet");
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
    var seedBytes = _keyMap[rootKeyId]!.getSeed();

    KeyData derived =
        await ED25519_HD_KEY.derivePath(derivationPath, seedBytes.toList());
    var derivedPrivateKey = ed.newKeyFromSeed(Uint8List.fromList(derived.key));

    var keyPair = Ed25519KeyPair(privateKey: derivedPrivateKey, keyId: keyId);
    _keyMap[keyId] = keyPair;

    return Future.value(keyPair);
  }

  @override
  Future<Uint8List> getPublicKey(String keyId) {
    final keyPair = _getKeyPair(keyId);
    return keyPair.getPublicKey();
  }

  @override
  Future<Ed25519KeyPair> getKeyPair(String keyId) async {
    return Future.value(_getKeyPair(keyId));
  }

  Ed25519KeyPair _getKeyPair(String keyId) {
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
          "For Bip32Ed25519Wallet the keyId is composed as {accountNumber}-{accountKeyId}, where both accountNumber and accountKeyId are positive integers");
    }
    return (accountNumber, accountKeyId);
  }

  static String _buildDerivationPath(
      String baseDerivationPath, int accountNumber, int accountKeyId) {
    List<String> parts = baseDerivationPath.split('/');
    parts[3] = "$accountNumber'";
    parts[5] = "$accountKeyId'";
    return parts.join('/');
  }
}
