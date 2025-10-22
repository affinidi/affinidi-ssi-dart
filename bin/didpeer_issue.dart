import 'dart:io';

import 'package:ssi/ssi.dart';

Future<void> main(List<String> args) async {
  final method = args.isNotEmpty ? args[0] : 'did:peer';
  print('Reproducer: issuing LD VC using $method');

  try {
    await runRepro(method);
    print('SUCCESS: VC issued');
    exit(0);
  } catch (e, st) {
    print('FAILED with exception: $e');
    print(st);
    exit(1);
  }
}

Future<void> runRepro(String didMethod) async {
  final wallet = PersistentWallet(InMemoryKeyStore());

  // Choose a key type supported for the test. Use p256 for ECDSA.
  final keyPair = await wallet.generateKey(keyType: KeyType.p256);

  final didManager = didMethod == 'did:key'
      ? DidKeyManager(store: InMemoryDidStore(), wallet: wallet)
      : DidPeerManager(store: InMemoryDidStore(), wallet: wallet);

  await didManager.addVerificationMethod(keyPair.id);

  final didDoc = await didManager.getDidDocument();
  final signer = await didManager.getSigner(didManager.assertionMethod.first);

  print('DID: ${didDoc.id}');
  print('Assertion method: ${didManager.assertionMethod.first}');

  final unsignedCredential = VcDataModelV1(
    context: [dmV1ContextUrl, 'https://schema.affinidi.io/TEmailV1R0.jsonld'],
    credentialSchema: [
      CredentialSchema(
        id: Uri.parse('https://schema.affinidi.io/TEmailV1R0.json'),
        type: 'JsonSchemaValidator2018',
      ),
    ],
    id: Uri.parse('urn:uuid:00000000-0000-0000-0000-000000000001'),
    issuer: Issuer.uri(signer.did),
    type: {'VerifiableCredential', 'Email'},
    issuanceDate: DateTime.now().toUtc(),
    credentialSubject: [
      CredentialSubject.fromJson({'id': signer.did, 'email': 'user@example.com'})
    ],
  );

  final suite = LdVcDm1Suite();

  final proofGenerator = signer.signatureScheme == SignatureScheme.ed25519
      ? DataIntegrityEddsaJcsGenerator(signer: signer)
      : DataIntegrityEcdsaJcsGenerator(signer: signer);

  final issued = await suite.issue(
    unsignedData: unsignedCredential,
    proofGenerator: proofGenerator,
  );

  print('Issued VC:');
  print(issued.toJson());
}
