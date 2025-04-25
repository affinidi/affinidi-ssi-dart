import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/did_document_fixtures.dart';

void main() {
  final seed = hexDecode(
    'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
  );

  final accountNumber = 24567;

  group('Test DID', () {
    late Bip32Ed25519Wallet wallet;
    late InMemoryKeyStore keyStore;
    late PublicKey accountPublicKey;

    setUp(() async {
      keyStore = InMemoryKeyStore();
      wallet = await Bip32Ed25519Wallet.fromSeed(seed, keyStore);
      accountPublicKey =
          await wallet.deriveKey(derivationPath: "m/44'/60'/0'/0'/0'");
    });

    test('generateDocument for did:peer:0 should match expected', () async {
      final expectedDid =
          'did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka';
      final expectedKeyType = KeyType.ed25519;

      final doc = DidPeer.generateDocument([accountPublicKey]);
      final actualDid = doc.id;
      final actualKeyType = accountPublicKey.type;

      final expectedDidDoc =
          jsonDecode(DidDocumentFixtures.didDocumentWithControllerPeer);
      final resolvedDidDocument = DidPeer.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toJson(), expectedDidDoc);

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('getDid for did:peer:0 should match expected', () async {
      final expectedDid =
          'did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka';

      final actualDid = DidPeer.getDid([accountPublicKey]);

      expect(actualDid, expectedDid);
    });

    test('generateDocument for did:peer:2 should start with did:peer:2.Ez6Mk',
        () async {
      final expectedDidPeerPrefix = 'did:peer:2.Ez6Mk';

      final expectedDid =
          'did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0';

      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.deriveKey(derivationPath: derivedKeyPath);
      final doc = DidPeer.generateDocument(
        [key, key],
        serviceEndpoint: 'https://denys.com/income',
      );
      final actualDid = doc.id;

      final expectedDidDocString =
          '{"id":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","@context":["https://www.w3.org/ns/did/v1","https://ns.did.ai/suites/multikey-2021/v1/"],"verificationMethod":[{"id":"#key-1","controller":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-2","controller":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-3","controller":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-4","controller":"did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0","type":"Ed25519VerificationKey2020","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"}],"authentication":["#key-3","#key-4"],"keyAgreement":["#key-1","#key-2"],"assertionMethod":["#key-3","#key-4"],"service":[{"id":"new-id","type":"DIDCommMessaging","serviceEndpoint":"https://denys.com/income"}]}';
      final resolvedDidDocument = DidPeer.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toJson(), jsonDecode(expectedDidDocString));

      expect(actualDid, startsWith(expectedDidPeerPrefix));
    });

    test('getDid for did:peer:2 should match expected', () async {
      final expectedDid =
          'did:peer:2.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2RlbnlzLmNvbS9pbmNvbWUiLCJhIjpbImRpZGNvbW0vdjIiXX0';

      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.deriveKey(derivationPath: derivedKeyPath);
      final actualDid = DidPeer.getDid(
        [
          key,
          key
        ], // Using same key twice for simplicity, matching generateDocument test
        serviceEndpoint: 'https://denys.com/income',
      );

      expect(actualDid, expectedDid);
    });

    test('public key derived from did should be the same', () async {
      final expectedPublicKey = Uint8List.fromList([
        237,
        1,
        56,
        162,
        237,
        26,
        224,
        161,
        48,
        164,
        81,
        159,
        5,
        116,
        7,
        215,
        243,
        177,
        23,
        231,
        108,
        55,
        87,
        112,
        225,
        15,
        181,
        233,
        26,
        194,
        131,
        237,
        234,
        165
      ]);

      final doc = DidPeer.generateDocument([accountPublicKey]);
      final actualPublicKey = doc.verificationMethod[0].asMultiKey();

      expect(actualPublicKey, expectedPublicKey);
    });
  });
}
