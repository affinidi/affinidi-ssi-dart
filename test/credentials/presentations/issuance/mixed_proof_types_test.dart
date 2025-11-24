import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('Mixed Proof Types in VP', () {
    late DidSigner vcSigner;
    late DidSigner vpSigner;

    setUp(() async {
      // Create ed25519 signer for VC
      final vcSeed = Uint8List.fromList(
          List.generate(32, (index) => index + 1)); // deterministic seed
      final ed25519Wallet = Bip32Ed25519Wallet.fromSeed(vcSeed);
      final ed25519Key = await ed25519Wallet.generateKey(keyId: "m/0'/0'/0'");
      final vcDidDoc = DidKey.generateDocument(ed25519Key.publicKey);
      vcSigner = DidSigner(
        did: vcDidDoc.id,
        didKeyId: vcDidDoc.verificationMethod[0].id,
        keyPair: ed25519Key,
        signatureScheme: SignatureScheme.ed25519,
      );

      // Create secp256k1 signer for VP
      final vpSeed = Uint8List.fromList(
          List.generate(32, (index) => index + 33)); // different seed
      final secp256k1Wallet = Bip32Wallet.fromSeed(vpSeed);
      final secp256k1Key =
          await secp256k1Wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'");
      final vpDidDoc = DidKey.generateDocument(secp256k1Key.publicKey);
      vpSigner = DidSigner(
        did: vpDidDoc.id,
        didKeyId: vpDidDoc.verificationMethod[0].id,
        keyPair: secp256k1Key,
        signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
      );
    });

    test('should create VP with multiple VCs having different proof types',
        () async {
      // Create VC with DataIntegrity proof (using ed25519 signer)
      final dataIntegrityVc = await _issueVcWithDataIntegrity(vcSigner);

      // Create VC with EcdsaSecp256k1Signature2019 proof (using secp256k1 signer)
      final secp256k1Vc = await _issueVcWithSecp256k1Proof(vpSigner);

      // Create VP containing both VCs
      final vp = MutableVpDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('uuid:test-vp-multiple-mixed-proofs'),
        type: {'VerifiablePresentation'},
        holder: MutableHolder.uri(vpSigner.did),
        verifiableCredential: [dataIntegrityVc, secp256k1Vc],
      );

      final vpProofGenerator = Secp256k1Signature2019Generator(
        signer: vpSigner,
        proofPurpose: ProofPurpose.authentication,
      );

      final issuedVp = await LdVpDm2Suite().issue(
        unsignedData: VpDataModelV2.fromMutable(vp),
        proofGenerator: vpProofGenerator,
      );

      expect(issuedVp, isNotNull);
      expect(issuedVp.verifiableCredential, hasLength(2));
      expect(issuedVp.proof.first.type, equals('EcdsaSecp256k1Signature2019'));

      // Verify VP
      final result = await UniversalPresentationVerifier().verify(issuedVp);
      expect(result.isValid, isTrue);
    });

    test(
        'should inject @context into DataIntegrityProof when embedded in VP with different proof type',
        () async {
      // Create VC with DataIntegrity proof (using ed25519 signer)
      final dataIntegrityVc = await _issueVcWithDataIntegrity(vcSigner);

      // Create VP containing the DataIntegrity VC, signed with secp256k1
      final vp = MutableVpDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('uuid:test-vp-context-injection'),
        type: {'VerifiablePresentation'},
        holder: MutableHolder.uri(vpSigner.did),
        verifiableCredential: [dataIntegrityVc],
      );

      final vpProofGenerator = Secp256k1Signature2019Generator(
        signer: vpSigner,
        proofPurpose: ProofPurpose.authentication,
      );

      final issuedVp = await LdVpDm2Suite().issue(
        unsignedData: VpDataModelV2.fromMutable(vp),
        proofGenerator: vpProofGenerator,
      );

      expect(issuedVp, isNotNull);
      expect(issuedVp.verifiableCredential, hasLength(1));

      // Verify that DataIntegrityProof has @context injected
      final vcJson = issuedVp.verifiableCredential.first.toJson();
      final vcProof = vcJson['proof'];
      expect(vcProof, isNotNull);

      if (vcProof is Map<String, dynamic>) {
        expect(vcProof['type'], equals('DataIntegrityProof'));
        expect(vcProof['@context'],
            equals('https://w3id.org/security/data-integrity/v2'));
      } else if (vcProof is List) {
        final dataIntegrityProof = vcProof.firstWhere(
          (p) => p is Map<String, dynamic> && p['type'] == 'DataIntegrityProof',
          orElse: () => null,
        );
        expect(dataIntegrityProof, isNotNull);
        expect(dataIntegrityProof['@context'],
            equals('https://w3id.org/security/data-integrity/v2'));
      }

      // Verify VP
      final result = await UniversalPresentationVerifier().verify(issuedVp);
      expect(result.isValid, isTrue);
    });

    test('should support ECDSA P-256 DataIntegrityProof VC in secp256k1 VP',
        () async {
      // Create P-256 signer for VC with ECDSA DataIntegrityProof
      final p256Seed = Uint8List.fromList(
          List.generate(32, (index) => index + 65)); // different seed
      final p256KeyPair = P256KeyPair.fromSeed(p256Seed);
      final p256DidDoc = DidKey.generateDocument(p256KeyPair.publicKey);
      final p256Signer = DidSigner(
        did: p256DidDoc.id,
        didKeyId: p256DidDoc.verificationMethod[0].id,
        keyPair: p256KeyPair,
        signatureScheme: SignatureScheme.ecdsa_p256_sha256,
      );

      // Create VC with ECDSA P-256 DataIntegrity proof
      final ecdsaVc = await _issueVcWithEcdsaDataIntegrity(p256Signer);

      // Create VP containing the ECDSA VC, signed with secp256k1
      final vp = MutableVpDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('uuid:test-vp-ecdsa-p256'),
        type: {'VerifiablePresentation'},
        holder: MutableHolder.uri(vpSigner.did),
        verifiableCredential: [ecdsaVc],
      );

      final vpProofGenerator = Secp256k1Signature2019Generator(
        signer: vpSigner,
        proofPurpose: ProofPurpose.authentication,
      );

      final issuedVp = await LdVpDm2Suite().issue(
        unsignedData: VpDataModelV2.fromMutable(vp),
        proofGenerator: vpProofGenerator,
      );

      expect(issuedVp, isNotNull);
      expect(issuedVp.verifiableCredential, hasLength(1));

      // Verify that ECDSA DataIntegrityProof has @context injected
      final vcJson = issuedVp.verifiableCredential.first.toJson();
      final vcProof = vcJson['proof'];
      expect(vcProof, isNotNull);

      if (vcProof is Map<String, dynamic>) {
        expect(vcProof['type'], equals('DataIntegrityProof'));
        expect(vcProof['cryptosuite'], equals('ecdsa-rdfc-2019'));
        expect(vcProof['@context'],
            equals('https://w3id.org/security/data-integrity/v2'));
      }

      // Verify VP
      final result = await UniversalPresentationVerifier().verify(issuedVp);
      expect(result.isValid, isTrue);
    });

    test(
        'should support secp256k1 VC (v1) in DataIntegrity VP (v2) - using different data models',
        () async {
      // Create VC with secp256k1 proof using DATA MODEL V1
      // Use vcSigner DID as the subject so it matches the VP holder
      final secp256k1VcV1 =
          await _issueVcV1WithSecp256k1Proof(vpSigner, vcSigner.did);

      // Create VP with DataIntegrity proof (v2) containing the v1 VC
      final vp = MutableVpDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('uuid:test-vp-v1-vc-in-v2-vp'),
        type: {'VerifiablePresentation'},
        holder: MutableHolder.uri(vcSigner.did), // VP holder matches VC subject
        verifiableCredential: [secp256k1VcV1],
      );

      final vpProofGenerator = DataIntegrityEddsaRdfcGenerator(
        signer: vcSigner,
        proofPurpose: ProofPurpose.authentication,
      );

      final issuedVp = await LdVpDm2Suite().issue(
        unsignedData: VpDataModelV2.fromMutable(vp),
        proofGenerator: vpProofGenerator,
      );

      expect(issuedVp, isNotNull);
      expect(issuedVp.verifiableCredential, hasLength(1));
      expect(issuedVp.proof.first.type, equals('DataIntegrityProof'));

      // Verify that the embedded v1 VC still has its secp256k1 proof
      final vcJson = issuedVp.verifiableCredential.first.toJson();
      final vcProof = vcJson['proof'];
      expect(vcProof, isNotNull);

      if (vcProof is Map<String, dynamic>) {
        expect(vcProof['type'], equals('EcdsaSecp256k1Signature2019'));
      }

      // Verify the VP context is v2 and VC context is v1
      final vpJson = issuedVp.toJson();
      expect(vpJson['@context'], contains(dmV2ContextUrl));
      expect(vcJson['@context'],
          contains('https://www.w3.org/2018/credentials/v1'));

      // Verify VP
      final result = await UniversalPresentationVerifier().verify(issuedVp);
      expect(result.isValid, isTrue);
    });

    // NOTE: The inverse scenario with SAME data model (non-DataIntegrity VC v2 in DataIntegrity VP v2)
    // is NOT supported. This is an architectural limitation, not a bug. The EcdsaSecp256k1Signature2019
    // scoped context exists in credentials/v1 but not in credentials/v2, and these contexts cannot be
    // merged due to protected term redefinition conflicts (both define 'proof' with @protected: true).
    //
    // However, the test above shows that using DIFFERENT data models (v1 VC in v2 VP) DOES work because
    // the VC and VP have separate @context arrays with no conflicts.
  });
}

Future<LdVcDataModelV2> _issueVcWithDataIntegrity(DidSigner signer) async {
  final unsignedVc = MutableVcDataModelV2(
    context: MutableJsonLdContext.fromJson([
      dmV2ContextUrl,
      'https://schema.affinidi.com/UserProfileV1-0.jsonld',
    ]),
    id: Uri.parse('uuid:test-vc-data-integrity'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(signer.did),
    validFrom: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({'name': 'Alice'}),
    ],
  );

  final proofGenerator = DataIntegrityEddsaRdfcGenerator(signer: signer);
  return await LdVcDm2Suite().issue(
    unsignedData: VcDataModelV2.fromMutable(unsignedVc),
    proofGenerator: proofGenerator,
  );
}

Future<LdVcDataModelV2> _issueVcWithSecp256k1Proof(DidSigner signer) async {
  final unsignedVc = MutableVcDataModelV2(
    context: MutableJsonLdContext.fromJson([
      dmV2ContextUrl,
      'https://schema.affinidi.com/UserProfileV1-0.jsonld',
    ]),
    id: Uri.parse('uuid:test-vc-secp256k1'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(signer.did),
    validFrom: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({'name': 'Bob'}),
    ],
  );

  final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
  return await LdVcDm2Suite().issue(
    unsignedData: VcDataModelV2.fromMutable(unsignedVc),
    proofGenerator: proofGenerator,
  );
}

Future<LdVcDataModelV2> _issueVcWithEcdsaDataIntegrity(DidSigner signer) async {
  final unsignedVc = MutableVcDataModelV2(
    context: MutableJsonLdContext.fromJson([
      dmV2ContextUrl,
      'https://schema.affinidi.com/UserProfileV1-0.jsonld',
    ]),
    id: Uri.parse('uuid:test-vc-ecdsa-p256'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(signer.did),
    validFrom: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({'name': 'Charlie'}),
    ],
  );

  final proofGenerator = DataIntegrityEcdsaRdfcGenerator(signer: signer);
  return await LdVcDm2Suite().issue(
    unsignedData: VcDataModelV2.fromMutable(unsignedVc),
    proofGenerator: proofGenerator,
  );
}

Future<LdVcDataModelV1> _issueVcV1WithSecp256k1Proof(
  DidSigner issuerSigner,
  String subjectDid,
) async {
  const dmV1ContextUrl = 'https://www.w3.org/2018/credentials/v1';

  final unsignedVc = MutableVcDataModelV1(
    context: MutableJsonLdContext.fromJson([dmV1ContextUrl]),
    id: Uri.parse('uuid:test-vc-v1-secp256k1'),
    type: {'VerifiableCredential'},
    issuer: Issuer.uri(issuerSigner.did),
    issuanceDate: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({
        'id': subjectDid,
      }),
    ],
  );

  final proofGenerator = Secp256k1Signature2019Generator(signer: issuerSigner);
  return await LdVcDm1Suite().issue(
    unsignedData: VcDataModelV1.fromMutable(unsignedVc),
    proofGenerator: proofGenerator,
  );
}
