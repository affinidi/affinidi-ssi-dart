import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('PersistentWallet with mldsa44 key type', () {
    late PersistentWallet wallet;

    setUp(() {
      wallet = PersistentWallet(InMemoryKeyStore());
    });

    test('generates an ML-DSA-44 key', () async {
      final kp =
          await wallet.generateKey(keyId: 'ml1', keyType: KeyType.mldsa44);
      expect(kp, isA<MlDsa44KeyPair>());
      expect(kp.publicKey.type, KeyType.mldsa44);
      expect(kp.publicKey.bytes.length, 1312);
    });

    test('persists and reloads an ML-DSA-44 key', () async {
      await wallet.generateKey(keyId: 'ml2', keyType: KeyType.mldsa44);
      final pk = await wallet.getPublicKey('ml2');
      expect(pk.type, KeyType.mldsa44);
      expect(pk.bytes.length, 1312);
    });

    test('sign and verify round-trip via wallet', () async {
      await wallet.generateKey(keyId: 'ml3', keyType: KeyType.mldsa44);
      final data = Uint8List.fromList([7, 8, 9]);
      final sig = await wallet.sign(data, keyId: 'ml3');
      expect(sig.length, 2420);
      final ok = await wallet.verify(data, signature: sig, keyId: 'ml3');
      expect(ok, isTrue);
    });

    test('getSupportedSignatureSchemes returns mldsa44', () async {
      await wallet.generateKey(keyId: 'ml4', keyType: KeyType.mldsa44);
      final schemes = await wallet.getSupportedSignatureSchemes('ml4');
      expect(schemes, contains(SignatureScheme.mldsa44));
    });

    test('generateKey returns the same key on second call with same ID',
        () async {
      final kp1 =
          await wallet.generateKey(keyId: 'ml5', keyType: KeyType.mldsa44);
      // Second call should return the stored key unchanged.
      final kp2 =
          await wallet.generateKey(keyId: 'ml5', keyType: KeyType.mldsa44);
      expect(kp1.publicKey.bytes, equals(kp2.publicKey.bytes));
    });

    test('encrypt via wallet throws SsiException for mldsa44 key', () async {
      await wallet.generateKey(keyId: 'ml6', keyType: KeyType.mldsa44);
      expect(
        () => wallet.encrypt(Uint8List(8), keyId: 'ml6'),
        throwsA(isA<SsiException>()),
      );
    });

    test('StoredKey JSON round-trip preserves mldsa44 key type', () async {
      const keyType = KeyType.mldsa44;
      final (kp, keyBlob) = MlDsa44KeyPair.generate();
      final stored = StoredKey(keyType: keyType, privateKeyBytes: keyBlob);
      final json = stored.toJson();
      final restored = StoredKey.fromJson(json);
      expect(restored.keyType, KeyType.mldsa44);
      expect(restored.privateKeyBytes.length, 3872);
      // Ensure restore actually reconstructs the same public key.
      final restoredKp =
          MlDsa44KeyPair.fromPrivateKey(restored.privateKeyBytes);
      expect(restoredKp.publicKey.bytes, equals(kp.publicKey.bytes));
    });
  });
}
