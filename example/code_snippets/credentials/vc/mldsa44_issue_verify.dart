// ignore_for_file: avoid_print

// Example: Issue and verify a Verifiable Credential using ML-DSA-44
// (FIPS 204 post-quantum signature) with the mldsa44-jcs-2024 cryptosuite.
//
// ML-DSA-44 support is experimental. Key sizes and serialisation formats
// follow the W3C vc-di-quantum-resistant draft and may change before
// standardisation is finalised.
import 'dart:convert';

import 'package:ssi/ssi.dart';

Future<void> main() async {
  // -----------------------------------------------------------------
  // 1. Generate an ML-DSA-44 key pair and build a minimal DID document.
  // -----------------------------------------------------------------
  final (keyPair, _) = MlDsa44KeyPair.generate(id: '#key-1');

  // Encode the public key as a Multikey verification method.
  // toMultikey() prepends the 2-byte ML-DSA-44 multicodec prefix (0x9024).
  final multikey = toMultikey(keyPair.publicKey.bytes, KeyType.mldsa44);
  final publicKeyMultibase = toMultiBase(multikey, base: MultiBase.base58bitcoin);

  const did = 'did:example:mldsa44-demo';
  final vmId = '$did#key-1';

  final vm = VerificationMethodMultibase(
    id: vmId,
    type: 'Multikey',
    controller: did,
    publicKeyMultibase: publicKeyMultibase,
  );

  final didDocument = DidDocument.create(
    id: did,
    verificationMethod: [vm],
    assertionMethod: [vm],
    authentication: [vm],
    capabilityInvocation: [vm],
    capabilityDelegation: [vm],
  );

  // -----------------------------------------------------------------
  // 2. Build the signer.
  // -----------------------------------------------------------------
  final signer = DidSigner(
    did: did,
    didKeyId: vmId,
    keyPair: keyPair,
    signatureScheme: SignatureScheme.mldsa44,
  );

  // -----------------------------------------------------------------
  // 3. Create a Verifiable Credential (using V1 data model).
  //    The mldsa44-jcs-2024 cryptosuite requires either:
  //      • https://www.w3.org/ns/credentials/v2 (VC v2 context), OR
  //      • https://w3id.org/security/data-integrity/v2 (Data Integrity context)
  //    in the credential @context.
  // -----------------------------------------------------------------
  final credential = MutableVcDataModelV1(
    context: MutableJsonLdContext.fromJson([
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/data-integrity/v2',
      'https://schema.affinidi.com/UserProfileV1-0.jsonld',
    ]),
    id: Uri.parse('uuid:mldsa44-example-001'),
    type: {'VerifiableCredential', 'UserProfile'},
    issuer: Issuer.uri(did),
    issuanceDate: DateTime.now().toUtc(),
    credentialSubject: [
      MutableCredentialSubject({'Fname': 'Alice', 'Lname': 'Smith'}),
    ],
  );

  // -----------------------------------------------------------------
  // 4. Issue the VC using the JCS-based cryptosuite (no network access
  //    required — JCS canonicalisation does not use JSON-LD processing).
  // -----------------------------------------------------------------
  final generator = DataIntegrityMldsaJcsGenerator(signer: signer);
  final issuedVc = await LdVcDm1Suite().issue(
    unsignedData: VcDataModelV1.fromMutable(credential),
    proofGenerator: generator,
  );

  print('Issued VC (JSON):\n${jsonEncode(issuedVc.toJson())}\n');

  // -----------------------------------------------------------------
  // 5. Verify the VC using a custom DID resolver that returns the
  //    document we constructed above.
  // -----------------------------------------------------------------
  final mockResolver = _StaticDidResolver(didDocument);

  final verifier = DataIntegrityMldsaJcsVerifier(
    verifierDid: did,
    didResolver: mockResolver,
  );

  final result = await verifier.verify(issuedVc.toJson());
  print('Verification result: ${result.isValid}');
  assert(result.isValid, 'Signature verification must succeed');

  // -----------------------------------------------------------------
  // 6. Demonstrate tamper detection.
  // -----------------------------------------------------------------
  final tamperedJson = Map<String, dynamic>.from(issuedVc.toJson())
    ..['credentialSubject'] = [
      {'Fname': 'Bob', 'Lname': 'Jones'},
    ];

  final tamperedResult = await verifier.verify(tamperedJson);
  print('Tampered VC verification: ${tamperedResult.isValid}');
  assert(!tamperedResult.isValid, 'Tampered credential must not verify');
}

// ---------------------------------------------------------------------------
// Minimal DID resolver that returns a pre-built DID document for any DID.
// In production use DidResolver with appropriate method handlers.
// ---------------------------------------------------------------------------
class _StaticDidResolver implements DidResolver {
  final DidDocument _doc;
  _StaticDidResolver(this._doc);

  @override
  Future<DidDocument> resolveDid(String did) async => _doc;
}
