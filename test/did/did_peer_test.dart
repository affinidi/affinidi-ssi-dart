import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
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
    late PublicKey accountPublicKey;

    setUp(() async {
      wallet = Bip32Ed25519Wallet.fromSeed(seed);
      accountPublicKey =
          (await wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'")).publicKey;
    });

    test('generateDocument for did:peer:0 should match expected', () async {
      final expectedDid =
          'did:peer:0z6MkiGLyAzSR45X3UovkdGnpH2TixJcYznTLqQ3ZLFkv91Ka';
      final expectedKeyType = KeyType.ed25519;

      final doc = DidPeer.generateDocument([accountPublicKey], []);
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

      final actualDid = DidPeer.getDid([accountPublicKey], []);

      expect(actualDid, expectedDid);
    });

    test('generate and resolve did:peer:2 with one service endpoint', () async {
      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.generateKey(keyId: derivedKeyPath);

      final service = ServiceEndpoint(
        id: '#my-service',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
      );

      final did = DidPeer.getDid(
        [key.publicKey],
        [key.publicKey],
        serviceEndpoints: [service],
      );

      final resolvedDoc = DidPeer.resolve(did);
      expect(resolvedDoc.id, did);
      expect(resolvedDoc.service, isNotNull);
      expect(resolvedDoc.service.length, 1);
      expect(resolvedDoc.service[0].id, '#my-service');
      expect(resolvedDoc.service[0].type, 'TestService');
      expect(
        (resolvedDoc.service[0].serviceEndpoint as StringEndpoint).url,
        'https://example.com/endpoint',
      );
    });

    test('generate and resolve did:peer:2 with multiple service endpoints',
        () async {
      final authKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'");
      final agreeKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/1'");

      final service1 = ServiceEndpoint(
        id: '#service-1',
        type: 'DIDCommMessaging',
        serviceEndpoint: const StringEndpoint('https://endpoint1.com'),
      );

      final service2 = ServiceEndpoint(
        id: '#service-2',
        type: 'DIDCommMessaging',
        serviceEndpoint: const MapEndpoint({'uri': 'https://endpoint2.com'}),
      );

      final did = DidPeer.getDid(
        [authKey.publicKey],
        [agreeKey.publicKey],
        serviceEndpoints: [service1, service2],
      );

      final resolvedDoc = DidPeer.resolve(did);

      expect(resolvedDoc.id, did);
      expect(resolvedDoc.service, isNotNull);
      expect(resolvedDoc.service.length, 2);
      expect(resolvedDoc.service[0].id, '#service-1');
      expect(resolvedDoc.service[0].type, 'DIDCommMessaging');
      expect(
        (resolvedDoc.service[0].serviceEndpoint as StringEndpoint).url,
        'https://endpoint1.com',
      );
      expect(resolvedDoc.service[1].id, '#service-2');
      expect(resolvedDoc.service[1].type, 'DIDCommMessaging');
      expect(
        (resolvedDoc.service[1].serviceEndpoint as MapEndpoint).data,
        {'uri': 'https://endpoint2.com'},
      );
    });

    test('generateDocument for did:peer:2 with separate keyAgreement keys',
        () async {
      final derivedKeyPath1 = "m/44'/60'/$accountNumber'/0'/0'";
      final derivedKeyPath2 = "m/44'/60'/$accountNumber'/0'/1'";

      final authKey = await wallet.generateKey(keyId: derivedKeyPath1);
      final agreeKey = await wallet.generateKey(keyId: derivedKeyPath2);

      final service = ServiceEndpoint(
        id: '#service-1',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
      );

      final doc = DidPeer.generateDocument(
        [authKey.publicKey],
        [agreeKey.publicKey],
        serviceEndpoints: [service],
      );

      // Check that keyAgreement contains only the agreement key
      expect(doc.keyAgreement.length, 1);

      // Check that authentication contains only the auth key
      expect(doc.authentication.length, 1);

      // Verify the DID contains both E and V prefixed keys
      expect(doc.id, contains('.Vz')); // Authentication key (V prefix)
      expect(doc.id, contains('.Ez')); // Agreement key (E prefix)
      expect(doc.id, contains('.S')); // Service (S prefix)

      // Verify verification methods are created correctly
      expect(doc.verificationMethod.length, 2);
      expect(doc.verificationMethod[0].id, '#key-1');
      expect(doc.verificationMethod[1].id, '#key-2');
    });

    test('generateDocument for did:peer:2 should start with did:peer:2.Vz6Mk',
        () async {
      final expectedDidPeerPrefix = 'did:peer:2.Vz6Mk';

      final expectedDid =
          'did:peer:2.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6IiNzZXJ2aWNlLTEiLCJ0IjoiVGVzdFNlcnZpY2UiLCJzIjoiaHR0cHM6Ly9kZW55cy5jb20vaW5jb21lIn0';

      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.generateKey(keyId: derivedKeyPath);

      final service = ServiceEndpoint(
        id: '#service-1',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://denys.com/income'),
      );

      final doc = DidPeer.generateDocument(
        [key.publicKey, key.publicKey],
        [key.publicKey, key.publicKey],
        serviceEndpoints: [service],
      );
      final actualDid = doc.id;

      final expectedDidDocString =
          '{"id":"did:peer:2.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6IiNzZXJ2aWNlLTEiLCJ0IjoiVGVzdFNlcnZpY2UiLCJzIjoiaHR0cHM6Ly9kZW55cy5jb20vaW5jb21lIn0","@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"verificationMethod":[{"id":"#key-1","controller":"did:peer:2.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6IiNzZXJ2aWNlLTEiLCJ0IjoiVGVzdFNlcnZpY2UiLCJzIjoiaHR0cHM6Ly9kZW55cy5jb20vaW5jb21lIn0","type":"Multikey","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-2","controller":"did:peer:2.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6IiNzZXJ2aWNlLTEiLCJ0IjoiVGVzdFNlcnZpY2UiLCJzIjoiaHR0cHM6Ly9kZW55cy5jb20vaW5jb21lIn0","type":"Multikey","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-3","controller":"did:peer:2.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6IiNzZXJ2aWNlLTEiLCJ0IjoiVGVzdFNlcnZpY2UiLCJzIjoiaHR0cHM6Ly9kZW55cy5jb20vaW5jb21lIn0","type":"Multikey","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"},{"id":"#key-4","controller":"did:peer:2.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6IiNzZXJ2aWNlLTEiLCJ0IjoiVGVzdFNlcnZpY2UiLCJzIjoiaHR0cHM6Ly9kZW55cy5jb20vaW5jb21lIn0","type":"Multikey","publicKeyMultibase":"z6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8"}],"authentication":["#key-1","#key-2"],"keyAgreement":["#key-3","#key-4"],"service":[{"id":"#service-1","type":"TestService","serviceEndpoint":"https://denys.com/income"}]}';
      final resolvedDidDocument = DidPeer.resolve(actualDid);
      expect(resolvedDidDocument.id, expectedDid);
      expect(resolvedDidDocument.toJson(), jsonDecode(expectedDidDocString));

      expect(actualDid, startsWith(expectedDidPeerPrefix));
    });

    test('getDid for did:peer:2 should match expected', () async {
      final expectedDid =
          'did:peer:2.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Vz6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.Ez6MkuTNHD7jWb6MMjStAiNajBifDNoFQVC6wmwAKz4MVjNP8.SeyJpZCI6IiNzZXJ2aWNlLTEiLCJ0IjoiVGVzdFNlcnZpY2UiLCJzIjoiaHR0cHM6Ly9kZW55cy5jb20vaW5jb21lIn0';

      final derivedKeyPath = "m/44'/60'/$accountNumber'/0'/0'";
      final key = await wallet.generateKey(keyId: derivedKeyPath);

      final service = ServiceEndpoint(
        id: '#service-1',
        type: 'TestService',
        serviceEndpoint: const StringEndpoint('https://denys.com/income'),
      );

      final actualDid = DidPeer.getDid(
        [key.publicKey, key.publicKey],
        [
          key.publicKey,
          key.publicKey
        ], // Using same key twice for simplicity, matching generateDocument test
        serviceEndpoints: [service],
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

      final doc = DidPeer.generateDocument([accountPublicKey], []);
      final actualPublicKey = doc.verificationMethod[0].asMultiKey();

      expect(actualPublicKey, expectedPublicKey);
    });
  });
}
