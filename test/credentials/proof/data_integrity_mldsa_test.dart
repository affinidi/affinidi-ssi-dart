import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A minimal DID resolver that returns a pre-built document for any DID.
class _MockDidResolver implements DidResolver {
  final DidDocument _doc;
  _MockDidResolver(this._doc);

  @override
  Future<DidDocument> resolveDid(String did) async => _doc;
}

/// Builds a minimal DID document with a single ML-DSA-44 Multikey verification
/// method and wires it into all signature-applicable relationships.
DidDocument _buildMlDsaDidDocument({
  required String did,
  required String vmId,
  required Uint8List publicKeyBytes,
}) {
  final multikey = toMultikey(publicKeyBytes, KeyType.mldsa44);
  final multibase = toMultiBase(multikey, base: MultiBase.base64UrlNoPad);

  final vm = VerificationMethodMultibase(
    id: vmId,
    type: 'Multikey',
    controller: did,
    publicKeyMultibase: multibase,
  );

  return DidDocument.create(
    id: did,
    verificationMethod: [vm],
    authentication: [vm],
    assertionMethod: [vm],
    capabilityInvocation: [vm],
    capabilityDelegation: [vm],
  );
}

/// Creates an ML-DSA-44 [DidSigner] together with a [MockDidResolver] backed
/// by a matching DID document. Optionally accepts a seed for deterministic
/// key generation.
Future<(DidSigner, _MockDidResolver)> _makeMldsaSigner({
  Uint8List? seed,
}) async {
  final MlDsa44KeyPair kp;
  if (seed != null) {
    final (pair, _) = await MlDsa44KeyPair.fromSeed(seed);
    kp = pair;
  } else {
    final (pair, _) = MlDsa44KeyPair.generate();
    kp = pair;
  }

  const did = 'did:example:mldsa44test';
  final vmId = '$did#key-1';

  final doc = _buildMlDsaDidDocument(
    did: did,
    vmId: vmId,
    publicKeyBytes: kp.publicKey.bytes,
  );

  final signer = DidSigner(
    did: did,
    didKeyId: vmId,
    keyPair: kp,
    signatureScheme: SignatureScheme.mldsa44,
  );

  return (signer, _MockDidResolver(doc));
}

/// Builds a simple unsigned VC for testing.
MutableVcDataModelV1 _buildUnsignedVc(String issuerDid) {
  return MutableVcDataModelV1(
    context: MutableJsonLdContext.fromJson([
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/data-integrity/v2',
      'https://schema.affinidi.com/UserProfileV1-0.jsonld',
    ]),
    id: Uri.parse('uuid:mldsa-test-123'),
    type: {'VerifiableCredential', 'UserProfile'},
    credentialSubject: [
      MutableCredentialSubject({'Fname': 'Alice', 'Lname': 'Smith'})
    ],
    issuanceDate: DateTime.parse('2024-01-01T00:00:00Z'),
    issuer: Issuer.uri(issuerDid),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  group('verifyMldsa44DataIntegritySignature helper', () {
    test('returns false for wrong-length signature', () async {
      final (kp, _) = MlDsa44KeyPair.generate();
      const did = 'did:example:x';
      final vmId = '$did#k1';
      final doc = _buildMlDsaDidDocument(
          did: did, vmId: vmId, publicKeyBytes: kp.publicKey.bytes);

      final resolver = _MockDidResolver(doc);
      final result = await verifyMldsa44DataIntegritySignature(
        'z${String.fromCharCodes(List.filled(10, 65))}', // short garbage
        did,
        Uri.parse(vmId),
        hashData: Uint8List(64),
        didResolver: resolver,
      );
      expect(result, isFalse);
    });

    test('returns false for tampered signature', () async {
      final (kp, _) = MlDsa44KeyPair.generate();
      const did = 'did:example:x';
      final vmId = '$did#k1';
      final doc = _buildMlDsaDidDocument(
          did: did, vmId: vmId, publicKeyBytes: kp.publicKey.bytes);
      final resolver = _MockDidResolver(doc);

      final hashData = Uint8List.fromList(List.generate(64, (i) => i));
      final goodSig = await kp.sign(hashData);
      final badSig = Uint8List.fromList(goodSig)..fillRange(0, 10, 0);

      final result = await verifyMldsa44DataIntegritySignature(
        toMultiBase(badSig, base: MultiBase.base64UrlNoPad),
        did,
        Uri.parse(vmId),
        hashData: hashData,
        didResolver: resolver,
      );
      expect(result, isFalse);
    });

    test('returns true for a valid signature', () async {
      final (kp, _) = MlDsa44KeyPair.generate();
      const did = 'did:example:x';
      final vmId = '$did#k1';
      final doc = _buildMlDsaDidDocument(
          did: did, vmId: vmId, publicKeyBytes: kp.publicKey.bytes);
      final resolver = _MockDidResolver(doc);

      final hashData = Uint8List.fromList(List.generate(64, (i) => i));
      final sig = await kp.sign(hashData);

      final result = await verifyMldsa44DataIntegritySignature(
        toMultiBase(sig, base: MultiBase.base64UrlNoPad),
        did,
        Uri.parse(vmId),
        hashData: hashData,
        didResolver: resolver,
      );
      expect(result, isTrue);
    });
  });

  group('mldsa44-rdfc-2024 cryptosuite', () {
    late DidSigner signer;
    late _MockDidResolver resolver;

    setUpAll(() async {
      final seed = Uint8List.fromList(List.generate(32, (i) => i + 7));
      (signer, resolver) = await _makeMldsaSigner(seed: seed);
    });

    test('generator rejects wrong signer scheme', () {
      // Build a P256 signer so the scheme check fails.
      final (kp, _) = P256KeyPair.generate();
      final doc = DidKey.generateDocument(kp.publicKey);
      final p256Signer = DidSigner(
        did: doc.id,
        didKeyId: doc.verificationMethod[0].id,
        keyPair: kp,
        signatureScheme: SignatureScheme.ecdsa_p256_sha256,
      );
      expect(
        () => DataIntegrityMldsaRdfcGenerator(signer: p256Signer),
        throwsA(isA<SsiException>()),
      );
    });

    test('issues a VC with mldsa44-rdfc-2024 proof (base64url-no-pad default)',
        () async {
      final vc = _buildUnsignedVc(signer.did);
      final generator = DataIntegrityMldsaRdfcGenerator(signer: signer);

      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: generator,
      );

      final proof = issued.toJson()['proof'] as Map<String, dynamic>;
      expect(proof['type'], 'DataIntegrityProof');
      expect(proof['cryptosuite'], 'mldsa44-rdfc-2024');
      expect(proof['proofValue'], startsWith('u'),
          reason: 'should use base64url-no-pad by default');
    });

    test('verifier validates an issued credential', () async {
      final vc = _buildUnsignedVc(signer.did);
      final generator = DataIntegrityMldsaRdfcGenerator(signer: signer);

      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: generator,
      );

      final verifier = DataIntegrityMldsaRdfcVerifier(
        issuerDid: signer.did,
        didResolver: resolver,
      );

      final result = await verifier.verify(issued.toJson());
      expect(result.isValid, isTrue, reason: result.errors.toString());
    });

    test('verifier rejects tampered proofValue', () async {
      final vc = _buildUnsignedVc(signer.did);
      final generator = DataIntegrityMldsaRdfcGenerator(signer: signer);
      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: generator,
      );

      final json = issued.toJson();
      final proof = Map<String, dynamic>.from(json['proof'] as Map);
      // Flip the second character of the encoded proof value.
      final pv = proof['proofValue'] as String;
      proof['proofValue'] =
          pv[0] + (pv[1] == 'A' ? 'B' : 'A') + pv.substring(2);
      json['proof'] = proof;

      final verifier = DataIntegrityMldsaRdfcVerifier(
        issuerDid: signer.did,
        didResolver: resolver,
      );
      final result = await verifier.verify(json);
      expect(result.isValid, isFalse);
    });

    test('RDFC verifier rejects a JCS-signed credential', () async {
      final vc = _buildUnsignedVc(signer.did);
      final jcsGenerator = DataIntegrityMldsaJcsGenerator(signer: signer);
      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: jcsGenerator,
      );

      final rdfcVerifier = DataIntegrityMldsaRdfcVerifier(
        issuerDid: signer.did,
        didResolver: resolver,
      );
      final result = await rdfcVerifier.verify(issued.toJson());
      expect(result.isValid, isFalse);
    });
  });

  group('mldsa44-jcs-2024 cryptosuite', () {
    late DidSigner signer;
    late _MockDidResolver resolver;

    setUpAll(() async {
      final seed = Uint8List.fromList(List.generate(32, (i) => i + 13));
      (signer, resolver) = await _makeMldsaSigner(seed: seed);
    });

    test('issues a VC with mldsa44-jcs-2024 proof (base64url-no-pad default)',
        () async {
      final vc = _buildUnsignedVc(signer.did);
      final generator = DataIntegrityMldsaJcsGenerator(signer: signer);

      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: generator,
      );

      final proof = issued.toJson()['proof'] as Map<String, dynamic>;
      expect(proof['type'], 'DataIntegrityProof');
      expect(proof['cryptosuite'], 'mldsa44-jcs-2024');
      expect(proof['proofValue'], startsWith('u'));
    });

    test('verifier validates an issued credential', () async {
      final vc = _buildUnsignedVc(signer.did);
      final generator = DataIntegrityMldsaJcsGenerator(signer: signer);

      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: generator,
      );

      final verifier = DataIntegrityMldsaJcsVerifier(
        verifierDid: signer.did,
        didResolver: resolver,
      );

      final result = await verifier.verify(issued.toJson());
      expect(result.isValid, isTrue, reason: result.errors.toString());
    });

    test('verifier rejects tampered proofValue', () async {
      final vc = _buildUnsignedVc(signer.did);
      final generator = DataIntegrityMldsaJcsGenerator(signer: signer);
      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: generator,
      );

      final json = issued.toJson();
      final proof = Map<String, dynamic>.from(json['proof'] as Map);
      final pv = proof['proofValue'] as String;
      proof['proofValue'] =
          pv[0] + (pv[1] == 'A' ? 'B' : 'A') + pv.substring(2);
      json['proof'] = proof;

      final verifier = DataIntegrityMldsaJcsVerifier(
        verifierDid: signer.did,
        didResolver: resolver,
      );
      final result = await verifier.verify(json);
      expect(result.isValid, isFalse);
    });

    test('JCS verifier rejects an RDFC-signed credential', () async {
      final vc = _buildUnsignedVc(signer.did);
      final rdfcGenerator = DataIntegrityMldsaRdfcGenerator(signer: signer);
      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: rdfcGenerator,
      );

      final jcsVerifier = DataIntegrityMldsaJcsVerifier(
        verifierDid: signer.did,
        didResolver: resolver,
      );
      final result = await jcsVerifier.verify(issued.toJson());
      expect(result.isValid, isFalse);
    });

    test('LdVcDm1Suite verifyIntegrity dispatches mldsa44-jcs-2024', () async {
      final vc = _buildUnsignedVc(signer.did);
      final generator = DataIntegrityMldsaJcsGenerator(signer: signer);
      final issued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(vc),
        proofGenerator: generator,
      );

      // Wrap in a custom suite that uses the mock resolver.
      final verifier = DataIntegrityMldsaJcsVerifier(
        verifierDid: signer.did,
        didResolver: resolver,
      );
      final result = await verifier.verify(issued.toJson());
      expect(result.isValid, isTrue);
    });

    test('ML-DSA JCS verifier rejects EdDSA-JCS signed credential', () async {
      // Create an EdDSA key pair and sign a credential with the EdDSA JCS suite.
      final edSeed = Uint8List.fromList(
          List.generate(32, (i) => i)); // 32-byte seed for Ed25519
      final edKp = Ed25519KeyPair.fromSeed(edSeed);
      final edDoc = DidKey.generateDocument(edKp.publicKey);
      final edSigner = DidSigner(
        did: edDoc.id,
        didKeyId: edDoc.verificationMethod[0].id,
        keyPair: edKp,
        signatureScheme: SignatureScheme.ed25519,
      );

      final edVc = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/data-integrity/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld',
        ]),
        id: Uri.parse('uuid:ed-vc-1'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({'Fname': 'Bob', 'Lname': 'Jones'})
        ],
        issuanceDate: DateTime.parse('2024-01-01T00:00:00Z'),
        issuer: Issuer.uri(edSigner.did),
      );

      final edGenerator = DataIntegrityEddsaJcsGenerator(signer: edSigner);
      final edIssued = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(edVc),
        proofGenerator: edGenerator,
      );

      // An ML-DSA-44 JCS verifier must reject this.
      final mldsaVerifier = DataIntegrityMldsaJcsVerifier(
        verifierDid: edSigner.did,
        didResolver: resolver, // resolver returns ML-DSA doc — mismatch is fine
      );
      final result = await mldsaVerifier.verify(edIssued.toJson());
      expect(result.isValid, isFalse,
          reason: 'ML-DSA verifier should reject EdDSA-signed credentials');
    });
  });
}
