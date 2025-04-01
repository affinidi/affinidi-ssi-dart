import 'package:affinidi_ssi/affinidi_ssi.dart';
import 'package:base_codecs/base_codecs.dart';
import 'package:test/test.dart';

void main() {
  final seed = hexDecode(
    // 'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
    'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
  );

  final accountNumber = 24567;

  group('Test DID', () {
    test('the main did peer should match to the expected value', () async {
      final expectedDid =
          'did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy';
      final expectedKeyType = KeyType.ed25519;

      final wallet = await Bip32Ed25519Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final doc = await DidPeer.create([keyPair]);
      final actualDid = doc.id;
      final actualKeyType = await keyPair.getKeyType();

      final expectedDidDocString =
          '{"id":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","verificationMethod":[{"id":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","controller":"did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"}],"authentication":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"capabilityDelegation":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"capabilityInvocation":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"],"keyAgreement":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#z6LSrY3Na7Bkq7f3ktzajpR7vQ4YCjyw9KCT1Y2tnjLLZsV5"],"assertionMethod":["did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy#6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy"]}';
      final resolvedDidDocument = await DidPeer.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toString(), expectedDidDocString);

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('a derived did keys should start with did:peer:2.Ez6Mk', () async {
      final expectedDidPeerPrefix = 'did:peer:2.Ez6Mk';

      final expectedDid =
          'did:peer:2.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0';

      final wallet = await Bip32Ed25519Wallet.fromSeed(seed);
      final derivedKeyId = "$accountNumber-0";
      final keyPair = await wallet.createKeyPair(derivedKeyId);
      final doc = await DidPeer.create(
        [keyPair, keyPair],
        serviceEndpoint: 'https://denys.com/income',
      );
      final actualDid = doc.id;

      final expectedDidDocString =
          '{"id":"did:peer:2.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","verificationMethod":[{"id":"#key-1","controller":"did:peer:2.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C"},{"id":"#key-2","controller":"did:peer:2.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C"},{"id":"#key-3","controller":"did:peer:2.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C"},{"id":"#key-4","controller":"did:peer:2.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Ez6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.Vz6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkvihZPJZAyHyMsKTd9pVX2pGTgL6a5UrVodSJVEWbF48C"}],"authentication":["#key-3","#key-4"],"keyAgreement":["#key-1","#key-2"],"assertionMethod":["#key-3","#key-4"],"service":[{"id":"new-id","type":"DIDCommMessaging","serviceEndpoint":"https://denys.com/income"}]}';
      final resolvedDidDocument = await DidPeer.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toString(), expectedDidDocString);

      expect(actualDid, startsWith(expectedDidPeerPrefix));
    });

    test('public key derived from did should be the same', () async {
      final expectedPublicKey =
          "6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy";

      final wallet = await Bip32Ed25519Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final doc = await DidPeer.create([keyPair]);
      final actualPublicKey = doc.verificationMethod[0].publicKeyMultibase;

      expect(actualPublicKey, expectedPublicKey);
    });
  });
}
