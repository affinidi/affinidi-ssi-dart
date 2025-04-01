import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final accountNumber = 24567;

  group('Test DID', () {
    test('the main did key should match to the expected value', () async {
      final expectedDid =
          'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2';
      final expectedKeyType = KeyType.secp256k1;

      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final doc = await DidKey.create([keyPair]);
      final actualDid = doc.id;
      final actualKeyType = await keyPair.getKeyType();

      final expectedDidDocString =
          '{"id":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","verificationMethod":[{"id":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","controller":"did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2","type":"Secp256k1Key2021","publicKeyMultibase":"zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"}],"authentication":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"capabilityDelegation":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"capabilityInvocation":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"keyAgreement":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"],"assertionMethod":["did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2#zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2"]}';
      final resolvedDidDocument = await DidKey.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toString(), expectedDidDocString);

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('a derived did keys should start with did:key:zQ3s', () async {
      final expectedDidKeyPrefix = 'did:key:zQ3s';

      final wallet = Bip32Wallet.fromSeed(seed);
      final derivedKeyId = "$accountNumber-0";
      final keyPair = await wallet.createKeyPair(derivedKeyId);
      final doc = await DidKey.create([keyPair]);
      final actualDid = doc.id;

      expect(actualDid, startsWith(expectedDidKeyPrefix));
    });

    test('did should be different if the wrong key type is provided', () async {
      final expectedDid =
          'did:key:zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj';
      final expectedKeyType = KeyType.secp256k1;

      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final doc = await DidKey.create([keyPair]);
      final actualDid = doc.id;
      final actualKeyType = await keyPair.getKeyType();

      expect(actualDid, isNot(equals(expectedDid)));
      expect(actualKeyType, expectedKeyType);
    });

    test('public key derived from did should be the same', () async {
      final expectedPublicKey =
          'Q3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2';

      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final doc = await DidKey.create([keyPair]);
      final actualPublicKey = doc.verificationMethod[0].publicKeyMultibase;

      expect(actualPublicKey, expectedPublicKey);
    });
  });
}
