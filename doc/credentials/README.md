
### Models

- Verifiable Credential Models define the structure and data within different VC versions, representing specific formats like JWT, SD-JWT, VC Data Model v1.1, and VC Data Model v1.2. They ensure consistent representation and handling of VC properties (e.g., issuer, subject, claims) for each format, facilitating interoperability by providing a standardized way to work with diverse VC formats.
- refer [Models](https://github.com/affinidi/affinidi-ssi-dart/tree/main/lib/src/credentials/models) for more implementation.
- This creates mutable/imutable verified credentials for example

```dart
  // Create a sample verifiable credential
  final credential = MutableVcDataModelV2(
      context: [DMV2ContextUrl],
      id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
      issuer: Issuer.uri(signer.did),
      type: {'VerifiableCredential', 'UniversityDegreeCredential'},
      validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
      validUntil: DateTime.parse('2028-01-01T12:00:00Z'),
      credentialSubject: [
        MutableCredentialSubject({
          'id': 'did:example:subject',
          'degree': {
            'type': 'BachelorDegree',
            'name': 'Bachelor of Science and Arts',
          },
        })
      ]);

```

#### Creating a new VC model/format

- Create your own VC format based on baseDataModel. refer this for implementation of [jwt](https://github.com/affinidi/affinidi-ssi-dart/blob/main/lib/src/credentials/jwt/jwt_data_model_v1.dart) based Vc implementation.

### Suites

- Verifiable Credential Suites handle the processing of VCs for specific formats, providing functionality to parse (using canParse and parse), verify cryptographic integrity (using verifyIntegrity), and serialize (using present) VCs.  They employ generics (SerializedType, VC, ParsedVC) to abstract over diverse VC representations and promote a modular, extensible design that can accommodate multiple VC formats.

- refer [Suites](https://github.com/affinidi/affinidi-ssi-dart/tree/main/lib/src/credentials/suites) for more detail implementation.

### Proofs

- Proofs are used to create and verify data authenticity and integrity, with creation and verification operations handled using `EmbeddedProofSuiteCreateOptions` and `EmbeddedProofSuiteVerifyOptions`, and managed by `EmbeddedProofGenerator` and `EmbeddedProofVerifier`

#### extending proof suites

- To support new ways of signing and verifying data within Linked Data, you create custom proof handling. This involves defining a new structure for your proof and the logic to create and validate these proofs. You'll need a class that describes your proof and separate classes to handle the generation (signing) and verification of these proofs.

- for example, refer this [secp256k1 signature suite](https://github.com/affinidi/affinidi-ssi-dart/blob/main/lib/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart) implementation.

- these proofGenerator and verifier can be used in issuing credential or presentation in suits.

- **proofGenerator** is used for issuing or creating a proof associate to different suites.

```dart

  final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );
```

- **proofVerifier** is used for verifying integrity of the proof against different verification option.

```dart

      final proofVerifier =
          Secp256k1Signature2019Verifier(issuerDid: signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());
```

#### creating custom DID signer and verifier for jwt based VCs

- This Did signer or custom signer is used for signing VC for SDJwt and verifier to verify the signature of sdjwt based credential
- for custom implementation refer this [didSigner](https://github.com/affinidi/affinidi-ssi-dart/blob/main/lib/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart#L196) and [didVerifier](https://github.com/affinidi/affinidi-ssi-dart/blob/main/lib/src/credentials/sdjwt/sdjwt_did_verifier.dart#L14)
- Use this signer and verifier in sdjwt suite for sign and verify.

