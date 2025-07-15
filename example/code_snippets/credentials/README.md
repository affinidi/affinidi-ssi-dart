# Credential Structure

VC handling is organised with **Models** that specify the data structure for various VC formats, ensuring consistent
representation.

**Suites** provide the processing logic for these formats, including parsing, cryptographic verification, and
serialisation, while **Proofs** handle the creation and validation of digital signatures to guarantee authenticity and
integrity of the VC.

## Models

Verifiable Credential Models define the structure and data within different VC versions, representing specific formats
like JWT, SD-JWT, VC Data Model v1.1, and VC Data Model v2. They ensure consistent representation and handling of VC
properties (e.g., issuer, subject, claims) for each format, facilitating interoperability by providing a standardised
way to work with diverse VC formats.

Refer to the [Models](https://github.com/affinidi/affinidi-ssi-dart/tree/main/lib/src/credentials/models) for more info
about the implementation.

This creates mutable verified credentials for example:

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

### Create a new VC Model

- To create your own VC format based on baseDataModel, refer to this sample implementation
  of [JWT VC](https://github.com/affinidi/affinidi-ssi-dart/blob/main/lib/src/credentials/jwt/jwt_data_model_v1.dart).

## Suites

Verifiable Credential Suites handle the processing of VCs for specific formats, providing functionality to parse (using
canParse and parse), verify cryptographic integrity (using verifyIntegrity), and serialise (using present) VCs. They
employ generics (SerialisedType, VC, ParsedVC) to abstract over diverse VC representations and promote a modular,
extensible design that can accommodate multiple VC formats.

Refer to the [Suites](https://github.com/affinidi/affinidi-ssi-dart/tree/main/lib/src/credentials/suites) for more info
about the implementation.

## Proofs

Proofs are used to create and verify data authenticity and integrity, with creation and verification operations handled
using `EmbeddedProofSuiteCreateOptions` and `EmbeddedProofSuiteVerifyOptions`, and managed by `EmbeddedProofGenerator`
and `EmbeddedProofVerifier`

### Extending the Proof Suites

To support new ways of signing and verifying data within Linked Data, you create custom proof handling. This involves
defining a new structure for your proof and the logic to create and validate these proofs. You'll need a class that
describes your proof and separate classes to handle the generation (signing) and verification of these proofs.

Refer to
this [secp256k1 signature suite](https://github.com/affinidi/affinidi-ssi-dart/blob/main/lib/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart)
for sample implementation.

The `proofGenerator` and `proofVerifier` can be used to issue credential or presentation suites.

- **proofGenerator** is used for issuing or creating a proof associated to different suites.

```dart

final proofGenerator = Secp256k1Signature2019Generator(
  signer: signer,
);

final issuedCredential = await
LdVcDm1Suite
().issue
(
unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
proofGenerator: proofGenerator
,
);
```

- **proofVerifier** is used for verifying the integrity of the proof against different verification option.

```dart

final proofVerifier =
Secp256k1Signature2019Verifier(issuerDid: signer.did);

final verificationResult =
    await
proofVerifier.verify
(
issuedCredential
.
toJson
(
)
);
```

#### Create Custom DID Signer and Verifier for JWT-based VCs

The DID signer is used for signing VC for SDJwt and verifier to verify the signature of sdjwt based credential

For sample custom implementation refer to
these [didSigner](https://github.com/affinidi/affinidi-ssi-dart/blob/main/lib/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart#L196)
and [didVerifier](https://github.com/affinidi/affinidi-ssi-dart/blob/main/lib/src/credentials/sdjwt/sdjwt_did_verifier.dart#L14).
Use the signer and verifier in SD-JWT suite for signing and verification.

