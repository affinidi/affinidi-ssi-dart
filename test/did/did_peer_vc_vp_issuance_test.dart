import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('did:peer:2 VC & VP issuance', () {
    late DidPeerManager manager;
    late PersistentWallet wallet;

    setUp(() async {
      final keyStore = InMemoryKeyStore();
      wallet = PersistentWallet(keyStore);
      manager = DidPeerManager(store: InMemoryDidStore(), wallet: wallet);
      await manager.init();

      // Generate a key for authentication and assertion
      final authKey = await wallet.generateKey(keyType: KeyType.secp256k1);
      await manager.addVerificationMethod(authKey.id, relationships: {
        VerificationRelationship.authentication,
        VerificationRelationship.assertionMethod,
      });

      // Generate a second key for keyAgreement
      final agreementKey = await wallet.generateKey(keyType: KeyType.secp256k1);
      await manager.addVerificationMethod(agreementKey.id, relationships: {
        VerificationRelationship.keyAgreement,
      });

      // Add a service endpoint to ensure did:peer:2
      await manager.addServiceEndpoint(ServiceEndpoint(
        id: '#service-1',
        type: 'DIDCommMessaging',
        serviceEndpoint: const StringEndpoint('https://example.com/endpoint'),
      ));
    });

    test('issue VC using did:peer:2 DID', () async {
      final didDocument = await manager.getDidDocument();
      expect(didDocument.id, startsWith('did:peer:2'));

      // Use first authentication key as signer
      final authVmId = didDocument.authentication.first.id; // e.g. '#key-1'
      final walletKeyId = await manager.getWalletKeyId(authVmId);
      expect(walletKeyId, isNotNull);
      final keyPair = await wallet.getKeyPair(walletKeyId!);

      final signer = DidSigner(
        did: didDocument.id,
        didKeyId: '${didDocument.id}$authVmId',
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
      );

      final unsignedCredential = MutableVcDataModelV2(
        context: [dmV2ContextUrl, 'https://schema.affinidi.com/UserProfileV1-0.jsonld'],
        id: Uri.parse('uuid:peer2-vc-1'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [MutableCredentialSubject({'Fname': 'Alice'})],
        issuer: Issuer.uri(signer.did),
        validFrom: DateTime.now(),
        validUntil: DateTime.now().add(const Duration(days: 365)),
      );

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issuedCredential = await LdVcDm2Suite().issue(
        unsignedData: VcDataModelV2.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      expect(issuedCredential, isNotNull);
      expect(issuedCredential.proof, isNotEmpty);
      expect(issuedCredential.issuer.id.toString(), didDocument.id);

      final verificationResult =
          await UniversalVerifier().verify(issuedCredential);
      expect(verificationResult.isValid, isTrue);
    });

    test('issue VP containing peer:2 issued VC', () async {
      final didDocument = await manager.getDidDocument();
      final authVmId = didDocument.authentication.first.id;
      final walletKeyId = await manager.getWalletKeyId(authVmId);
      final keyPair = await wallet.getKeyPair(walletKeyId!);

      final signer = DidSigner(
        did: didDocument.id,
        didKeyId: '${didDocument.id}$authVmId',
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
      );

      // Issue a VC first
      final unsignedCredential = MutableVcDataModelV2(
        context: [dmV2ContextUrl, 'https://schema.affinidi.com/UserProfileV1-0.jsonld'],
        id: Uri.parse('uuid:peer2-vc-2'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [MutableCredentialSubject({'Fname': 'Bob'})],
        issuer: Issuer.uri(signer.did),
        validFrom: DateTime.now(),
        validUntil: DateTime.now().add(const Duration(days: 365)),
      );
      final vcProofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issuedCredential = await LdVcDm2Suite().issue(
        unsignedData: VcDataModelV2.fromMutable(unsignedCredential),
        proofGenerator: vcProofGenerator,
      );

      // Build VP with the issued VC
      final mutableVp = MutableVpDataModelV2(
        context: [dmV2ContextUrl],
        id: Uri.parse('uuid:peer2-vp-1'),
        type: {'VerifiablePresentation'},
        holder: MutableHolder.uri(signer.did),
        verifiableCredential: [issuedCredential],
      );

      final vpProofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issuedPresentation = await LdVpDm2Suite().issue(
        unsignedData: VpDataModelV2.fromMutable(mutableVp),
        proofGenerator: vpProofGenerator,
      );

      expect(issuedPresentation, isNotNull);
      expect(issuedPresentation.proof, isNotEmpty);
      expect(issuedPresentation.holder?.id.toString(), didDocument.id);
      expect(issuedPresentation.verifiableCredential, hasLength(1));
      expect(issuedPresentation.verifiableCredential.first.issuer.id.toString(),
          didDocument.id);

      // Basic structural checks are sufficient; presentation verification handled elsewhere.
    });
  });
}
