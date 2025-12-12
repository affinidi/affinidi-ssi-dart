# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## 2025-12-12

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v3.1.1`](#ssi---v311)

---

#### `ssi` - `v3.1.1`

 - **FIX**: jwt vc verification for all supported alg.
 - **FIX**: revocation list 2020 handle numeric index (#231).


## 2025-12-11

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v3.1.1`](#ssi---v311)

---

#### `ssi` - `v3.1.1`

 - **FIX**: jwt vc verification for all supported alg.
 - **FIX**: revocation list 2020 handle numeric index (#231).

## 3.1.1

 - **FIX**: jwt vc verification for all supported alg.
 - **FIX**: revocation list 2020 handle numeric index (#231).


## 2025-12-03

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v3.1.0`](#ssi---v310)

---

#### `ssi` - `v3.1.0`

 - **FEAT**: add JSON-LD exception handling and error propagation (#230).

## 3.1.0

 - **FEAT**: add JSON-LD exception handling and error propagation (#230).


## 2025-11-28

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v3.0.2`](#ssi---v302)

---

#### `ssi` - `v3.0.2`

 - **FIX**: changelog entry (#229).

## 3.0.2

 - **FIX**: changelog entry (#229).


## 2025-11-28

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v3.0.1`](#ssi---v301)

---

#### `ssi` - `v3.0.1`

 - **FIX**: updated changelog entry for v3 (#228).

## 3.0.1

 - **FIX**: updated changelog entry for v3 (#228).


## 2025-11-28

### Changes

---

Packages with breaking changes:

 - [`ssi` - `v3.0.0`](#ssi---v300)

Packages with other changes:

 - There are no other changes in this release.

---

#### `ssi` - `v3.0.0`

- **BREAKING**: `VerifiableCredential` MUST exist in VC type field (v1) (#205).
- **BREAKING**: `VerifiablePresentation` MUST exist in VP type fields (v1 & v2) (#216).
- **BREAKING**: Data Integrity proofs require proper `@context` entries (VC v2 context OR Data Integrity context) (#198).
- **BREAKING**: Service types must use `StringServiceType` or `SetServiceType` classes (#208).
- **BREAKING**: Issuer DID must match proof verificationMethod DID (#199).
- **BREAKING**: Proof IDs must be unique and non-empty within credentials (#201).
- **BREAKING**: Proof types cannot be null or empty strings (#202).
- **BREAKING**: Proof purpose must match document type - VCs use `assertionMethod`, VPs use `authentication` (#214).
- **BREAKING**: Credentials and presentations must be within their validity period for verification (#206).
- **BREAKING**: SD-JWT credentials validate exp and nbf claims (#211).
- **BREAKING**: Stricter proof field structure validation (#204).
- **FEAT**: automatic nonce generation for data integrity proofs to prevent replay attacks (#215).
- **FIX**: tests and melos issue (#203).
- **FIX**: type issues (#218).

## 3.0.0

> Note: This release has breaking changes.

- **BREAKING**: `VerifiableCredential` MUST exist in VC type field (v1) (#205).
- **BREAKING**: `VerifiablePresentation` MUST exist in VP type fields (v1 & v2) (#216).
- **BREAKING**: Data Integrity proofs require proper `@context` entries (VC v2 context OR Data Integrity context) (#198).
- **BREAKING**: Service types must use `StringServiceType` or `SetServiceType` classes (#208).
- **BREAKING**: Issuer DID must match proof verificationMethod DID (#199).
- **BREAKING**: Proof IDs must be unique and non-empty within credentials (#201).
- **BREAKING**: Proof types cannot be null or empty strings (#202).
- **BREAKING**: Proof purpose must match document type - VCs use `assertionMethod`, VPs use `authentication` (#214).
- **BREAKING**: Credentials and presentations must be within their validity period for verification (#206).
- **BREAKING**: SD-JWT credentials validate exp and nbf claims (#211).
- **BREAKING**: Stricter proof field structure validation (#204).
- **FEAT**: automatic nonce generation for data integrity proofs to prevent replay attacks (#215).
- **FIX**: tests and melos issue (#203).
- **FIX**: type issues (#218).

This major release enforces strict W3C specification compliance and introduces important security enhancements for Verifiable Credentials and Decentralized Identifiers.

### What This Release Provides

- Improved W3C VC Data Model v1.1 and v2.0 compliance
- Improved W3C Data Integrity specification compliance
- Enhanced security against fraudulent credentials
- Temporal validation for credential lifecycle management
- Stricter proof validation and consistency checks
- Improved DID service endpoint handling
- Automatic nonce generation for replay attack prevention
- Better interoperability with W3C-compliant systems

### Migration Guide

#### Update Credential Types

```dart
// For Verifiable Credentials (v1)
final vc = VcDataModelV1(
  type: {'VerifiableCredential', 'UserCredential'}, // Must include VerifiableCredential
  // ...
);

// For Verifiable Presentations (v1 & v2)
final vp = VpDataModelV1(
  type: {'VerifiablePresentation', 'CustomPresentation'}, // Must include VerifiablePresentation
  // ...
);
```

#### Update Contexts for Data Integrity

```dart
final vc = MutableVcDataModelV2(
  context: [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/security/data-integrity/v2', // Required for Data Integrity proofs
  ],
  // ...
);
```

#### Update Service Endpoints

```dart
// Single type
final service = ServiceEndpoint(
  id: 'service-1',
  type: StringServiceType('MessagingService'),
  serviceEndpoint: 'https://example.com',
);

// Multiple types
final service = ServiceEndpoint(
  id: 'service-2',
  type: SetServiceType(['MessagingService', 'CredentialRepository']),
  serviceEndpoint: 'https://example.com',
);
```

#### Ensure Proof Consistency

```dart
// Issuer DID must match verificationMethod DID
final issuerDid = 'did:example:issuer123';
final vc = await suite.issue(
  credential: MutableVcDataModelV1(
    issuer: Issuer.uri(issuerDid),
    // ...
  ),
  signer: signer, // Must have matching DID
);
```

#### Handle Temporal Validation

```dart
final now = DateTime.now();
final vc = MutableVcDataModelV2(
  issuanceDate: now,
  expirationDate: now.add(Duration(days: 365)),
  // ...
);

// Verification will fail if outside validity period
final result = await verifier.verify(credential);
```

### Common Issues and Solutions

**Issue 1: "proof type is required and cannot be empty"**

- Solution: Ensure all proofs have a valid, non-empty type string

**Issue 2: "invalid proof purpose, expected assertionMethod/authentication"**

- Solution: VCs should use `assertionMethod`, VPs should use `authentication`

**Issue 3: "Missing required context"**

- Solution: Add Data Integrity context when using Data Integrity proof types

**Issue 4: "VerifiableCredential/VerifiablePresentation must exist in type"**

- Solution: Include the base type in your type array

**Issue 5: "Service type must use StringServiceType or SetServiceType"**

- Solution: Wrap service type strings in `StringServiceType()` or `SetServiceType()`

**Issue 6: "Credential has expired"**

- Solution: Ensure credentials are within their validity period, or reissue expired credentials

**Issue 7: "`credentialStatus` property must not exceed 5 items"**

- Solution: V2 credentials can have a maximum of 5 credentialStatus entries; reduce the number of status items

### Additional Resources

- [W3C Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/)
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)


## 2025-11-26

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.20.0`](#ssi---v2200)

---

#### `ssi` - `v2.20.0`

 - **FIX**: null safe toJson for credential status id (#224).
 - **FEAT**: add JWK validation against issuer did (#226).


## 2025-11-26

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.20.0`](#ssi---v2200)

---

#### `ssi` - `v2.20.0`

 - **FIX**: null safe toJson for credential status id (#224).
 - **FEAT**: add JWK validation against issuer did (#226).

## 2.20.0

 - **FIX**: null safe toJson for credential status id (#224).
 - **FEAT**: add JWK validation against issuer did (#226).


## 2025-11-24

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.19.3`](#ssi---v2193)

---

#### `ssi` - `v2.19.3`

 - **FIX**: support secp256k1 VPs that include DataIntegrityProof VCs (#220).

## 2.19.3

 - **FIX**: support secp256k1 VPs that include DataIntegrityProof VCs (#220).


## 2025-11-24

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.19.2`](#ssi---v2192)

---

#### `ssi` - `v2.19.2`

 - **FIX**: better jwt errors for unsupported model versions (#221).

## 2.19.2

 - **FIX**: better jwt errors for unsupported model versions (#221).


## 2025-11-18

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.19.1`](#ssi---v2191)

---

#### `ssi` - `v2.19.1`

 - **FIX**: didweb test failures by using mock did resolver (#217).

## 2.19.1

 - **FIX**: didweb test failures by using mock did resolver (#217).


## 2025-11-18

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.19.0`](#ssi---v2190)

---

#### `ssi` - `v2.19.0`

 - **FEAT**: add custom DID resolvers and base58 public key support (#209).

## 2.19.0

 - **FEAT**: add custom DID resolvers and base58 public key support (#209).


## 2025-11-17

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.18.0`](#ssi---v2180)

---

#### `ssi` - `v2.18.0`

 - **FEAT**: export full public_key_utils.dart (#213).

## 2.18.0

 - **FEAT**: export full public_key_utils.dart (#213).


## 2025-11-12

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.17.1`](#ssi---v2171)

---

#### `ssi` - `v2.17.1`

 - **FIX**: accept lists with one element (#210).

## 2.17.1

 - **FIX**: accept lists with one element (#210).


## 2025-11-04

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.17.0`](#ssi---v2170)

---

#### `ssi` - `v2.17.0`

 - **FEAT**: added context to the default document loader of data integrity verifier (#200).
 - **DOCS**: revocation vc issuance example and tests (#197).


## 2025-11-04

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.17.0`](#ssi---v2170)

---

#### `ssi` - `v2.17.0`

 - **FEAT**: added context to the default document loader of data integrity verifier (#200).
 - **DOCS**: revocation vc issuance example and tests (#197).

## 2.17.0

 - **FEAT**: added context to the default document loader of data integrity verifier (#200).
 - **DOCS**: revocation vc issuance example and tests (#197).


## 2025-10-24

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.16.0`](#ssi---v2160)

---

#### `ssi` - `v2.16.0`

 - **FEAT**: export DidSignerAdapter (#196).

## 2.16.0

 - **FEAT**: export DidSignerAdapter (#196).


## 2025-10-23

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.15.1`](#ssi---v2151)

---

#### `ssi` - `v2.15.1`

 - **FIX**: did peer verification method id and did peer 0 relationships (#195).

## 2.15.1

 - **FIX**: did peer verification method id and did peer 0 relationships (#195).


## 2025-10-17

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.15.0`](#ssi---v2150)

---

#### `ssi` - `v2.15.0`

 - **FEAT**: implement DidWeb.generateDocument functionality (#192).

## 2.15.0

 - **FEAT**: implement DidWeb.generateDocument functionality (#192).


## 2025-10-17

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.14.2`](#ssi---v2142)

---

#### `ssi` - `v2.14.2`

 - **FIX**: rejection sampling for p256/p384/p521 keys from seed (#190).
 - **FIX**: improve secp256k1 jws verifier to support DER encoded signatures (#186).
 - **FIX**: fix jcs hash calculation on issuance (#193).


## 2025-10-17

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.14.2`](#ssi---v2142)

---

#### `ssi` - `v2.14.2`

 - **FIX**: rejection sampling for p256/p384/p521 keys from seed (#190).
 - **FIX**: improve secp256k1 jws verifier to support DER encoded signatures (#186).
 - **FIX**: fix jcs hash calculation on issuance (#193).

## 2.14.2

 - **FIX**: rejection sampling for p256/p384/p521 keys from seed (#190).
 - **FIX**: improve secp256k1 jws verifier to support DER encoded signatures (#186).
 - **FIX**: fix jcs hash calculation on issuance (#193).


## 2025-10-10

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.14.1`](#ssi---v2141)

---

#### `ssi` - `v2.14.1`

 - **FIX**: add check for type to be VerifiableCredential (#191).

## 2.14.1

 - **FIX**: add check for type to be VerifiableCredential (#191).


## 2025-10-09

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.14.0`](#ssi---v2140)

---

#### `ssi` - `v2.14.0`

 - **FEAT**: secp256k1 key pair factory from seed (#189).

## 2.14.0

 - **FEAT**: secp256k1 key pair factory from seed (#189).


## 2025-10-08

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.13.0`](#ssi---v2130)

---

#### `ssi` - `v2.13.0`

 - **FEAT**: add holder binding verifier (#188).

## 2.13.0

 - **FEAT**: add holder binding verifier (#188).


## 2025-08-28

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.12.4`](#ssi---v2124)

---

#### `ssi` - `v2.12.4`

 - **FIX**: return did key id correctly (#184).

## 2.12.4

 - **FIX**: return did key id correctly (#184).


## 2025-08-15

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.12.3`](#ssi---v2123)

---

#### `ssi` - `v2.12.3`

 - **FIX**: Update vc revocation verifier (#182).

## 2.12.3

 - **FIX**: Update vc revocation verifier (#182).


## 2025-08-12

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.12.2`](#ssi---v2122)

---

#### `ssi` - `v2.12.2`

 - **FIX**: use the utc time in examples to fix the failing vp when verified (#181).

## 2.12.2

 - **FIX**: use the utc time in examples to fix the failing vp when verified (#181).


## 2025-08-07

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.12.1`](#ssi---v2121)

---

#### `ssi` - `v2.12.1`

 - **DOCS**: update change log with missing info (#179).

## 2.12.1

 - **DOCS**: update change log with missing info (#179).


## 2025-08-07

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.12.0`](#ssi---v2120)

---

#### `ssi` - `v2.12.0`

 - **FEAT**: enhance UniversalPresentationVerifier to allow custom credential verifiers (#176).

## 2.12.0

 - **FEAT**: enhance UniversalPresentationVerifier to allow custom credential verifiers (#176).

 - **UniversalPresentationVerifier**
    - Updated UniversalPresentationVerifier to use UniversalVerifier for individual credential verification within presentations.
    - Added support for custom VC verifiers (customVclVerifiers) to allow more flexible credential-level verification.

  - **VpIntegrityVerifier**
    - Updated to handle VP-level integrity checks only. Individual credentials within the VP should be verified using VcIntegrityVerifier.

## 2025-08-04

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.11.3`](#ssi---v2113)

---

#### `ssi` - `v2.11.3`

 - **FIX**: initial DID verifier update (#172).

## 2.11.3

 - **FIX**: initial DID verifier update (#172).


## 2025-08-01

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.11.2`](#ssi---v2112)

---

#### `ssi` - `v2.11.2`

 - **REFACTOR**: improve data integrity suite naming and add JCS compliance tests (#178).

## 2.11.2

 - **REFACTOR**: improve data integrity suite naming and add JCS compliance tests (#178).


## 2025-07-30

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.11.1`](#ssi---v2111)

---

#### `ssi` - `v2.11.1`

 - **FIX**: jcs proof context (#175).

## 2.11.1

 - **FIX**: jcs proof context (#175).


## 2025-07-29

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.11.0`](#ssi---v2110)

---

#### `ssi` - `v2.11.0`

 - **FEAT**: jcs variation (#170).

## 2.11.0

 - **FEAT**: jcs variation (#170).


## 2025-07-29

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.10.4`](#ssi---v2104)

---

#### `ssi` - `v2.10.4`

 - **FIX**: wasm compatibility (#173).

## 2.10.4

 - **FIX**: wasm compatibility (#173).


## 2025-07-28

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.10.3`](#ssi---v2103)

---

#### `ssi` - `v2.10.3`

 - **FIX**: vc signature (#169).

## 2.10.3

 - **FIX**: vc signature (#169).


## 2025-07-28

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.10.2`](#ssi---v2102)

---

#### `ssi` - `v2.10.2`

 - **REFACTOR**: remove live key (#166).

## 2.10.2

 - **REFACTOR**: remove live key (#166).


## 2025-07-28

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.10.1`](#ssi---v2101)

---

#### `ssi` - `v2.10.1`

 - **FIX**: remove obsolete workaround for key generation (#143).

## 2.10.1

 - **FIX**: remove obsolete workaround for key generation (#143).


## 2025-07-25

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.10.0`](#ssi---v2100)

---

#### `ssi` - `v2.10.0`

 - **FEAT**: improve didverifier (#156).

## 2.10.0

 - **FEAT**: improve didverifier (#156).


## 2025-07-25

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.9.1`](#ssi---v291)

---

#### `ssi` - `v2.9.1`

 - **FIX**: package publishing.

## 2.9.1

 - **FIX**: package publishing.


## 2025-07-24

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.9.0`](#ssi---v290)

---

#### `ssi` - `v2.9.0`

 - **FEAT**: expose X and Y coordinates on PublicKey JWK conversion (#157).

## 2.9.0

 - **FEAT**: expose X and Y coordinates on PublicKey JWK conversion (#157).


## 2025-07-24

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.8.2`](#ssi---v282)

---

#### `ssi` - `v2.8.2`

 - **FIX**: remove invalid TODOs and add DidSigner validation (#158).

## 2.8.2

 - **FIX**: remove invalid TODOs and add DidSigner validation (#158).


## 2025-07-23

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.8.1`](#ssi---v281)

---

#### `ssi` - `v2.8.1`

 - **FIX**: fix revocation verifier (#164).

## 2.8.1

 - **FIX**: fix revocation verifier (#164).


## 2025-07-22

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.8.0`](#ssi---v280)

---

#### `ssi` - `v2.8.0`

 - **FEAT**: extend vp universal verifier (#162).

## 2.8.0

 - **FEAT**: extend vp universal verifier (#162).


## 2025-07-22

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.7.0`](#ssi---v270)

---

#### `ssi` - `v2.7.0`

 - **FEAT**: extend universal verifiers (#161).

## 2.7.0

 - **FEAT**: extend universal verifiers (#161).


## 2025-07-22

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.6.0`](#ssi---v260)

---

#### `ssi` - `v2.6.0`

 - **FEAT**: add customDocumentLoader to vp verifyIntegrity (#160).

## 2.6.0

 - **FEAT**: add customDocumentLoader to vp verifyIntegrity (#160).


## 2025-07-16

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.5.0`](#ssi---v250)

---

#### `ssi` - `v2.5.0`

 - **FEAT**: implement delegation vc verifier (#146).

## 2.5.0

 - **FEAT**: implement delegation vc verifier (#146).


## 2025-07-16

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.4.0`](#ssi---v240)

---

#### `ssi` - `v2.4.0`

 - **FEAT**: update secp keys decryption (#150).

## 2.4.0

 - **FEAT**: update secp keys decryption (#150).


## 2025-07-16

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.3.2`](#ssi---v232)

---

#### `ssi` - `v2.3.2`

 - **FIX**: specify 'meta' dependency version (#154).
 - **FIX**: change meta dependency to 'any' and update version to '2.3.1' (#153).
 - **DOCS**: fix the VCDM 2 context in description (#152).

## 2.3.2

 - **FIX**: specify 'meta' dependency version (#154).
 - **FIX**: change meta dependency to 'any' and update version to '2.3.1' (#153).
 - **DOCS**: fix the VCDM 2 context in description (#152).


## 2025-07-15

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.3.0`](#ssi---v230)

---

#### `ssi` - `v2.3.0`

 - **FEAT**: Add custom document loader support for verifiable credential verification (#141).

## 2.3.0

 - **FEAT**: Add custom document loader support for verifiable credential verification (#141).


## 2025-07-15

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.2.1`](#ssi---v221)

---

#### `ssi` - `v2.2.1`

 - **DOCS**: fix the VCDM 2 description (#151).

## 2.2.1

 - **DOCS**: fix the VCDM 2 description (#151).


## 2025-07-10

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.2.0`](#ssi---v220)

---

#### `ssi` - `v2.2.0`

 - **FEAT**: v2 release with major improvements.

## 2.2.0

 - **FEAT**: v2 release with major improvements.


## 2025-07-10

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v2.1.0`](#ssi---v210)

---

#### `ssi` - `v2.1.0`

 - **FEAT**: v2 release with major improvements.

## 2.1.0

 - **FEAT**: v2 release with major improvements.

 - Replace JWT dependency from `jose_plus` to `dart_jsonwebtoken`.
 - Introduce unified DID Manager for simplified DID management:
   - Single interface for all DID methods with automatic document generation.
   - Seamless wallet integration with built-in key mapping and relationship management.
   - Smart key handling: automatic Ed25519 → X25519 conversion for key agreement.
   - Direct signing operations via `manager.getSigner()` without manual key lookups.
   - Flexible verification relationships with sensible defaults per key type.
   - Persistent key storage support through pluggable `DidStore` interface.
 - Align all signature schemes with JOSE standards; cryptosuite mappings updated (e.g., `eddsa-rdfc-2022` → `ed25519`).
 - Improve Ed25519 to X25519 conversion with RFC 7748 clamping and proper SHA-512 hashing.
 - Add `ed25519PublicToX25519Public()` utility for direct Ed25519 to X25519 key conversion.
 - Standardize `computeEcdhSecret()` interface across all key pair types using `@override` annotations.
 - Extend `did:peer` support with multibase key type detection, new relationship prefixes (`A`, `I`, `D`), and automatic X25519 derivation.
 - Improve service endpoint handling with `ServiceEndpointValue` and automatic service ID generation.
 ### Breaking Changes
 - Remove `w3c` field from `SignatureScheme` enum.
 - Simplify `SignatureScheme`: merge `eddsa_sha512` and `ed25519_sha256` into single `ed25519`.
 - Change Ed25519 algorithm identifier from `'EdDSA'` to `'Ed25519'`.
 - `DidSigner` now accepts a `String did` instead of a `DidDocument`.
 - Remove the `publicKey` getter from `DidSigner`.
 - `ed25519KeyToX25519PublicKey()` return type changed from `Future<SimplePublicKey>` to `Future<PublicKey>`.
 - `ed25519PublicToX25519Public()` return type changed from `String` to `Uint8List`.


## 2025-07-03

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.7.0`](#ssi---v170)

---

#### `ssi` - `v1.7.0`

 - **FEAT**: configure AWS KMS wallet tests as integration tests (#131).

## 1.7.0

 - **FEAT**: configure AWS KMS wallet tests as integration tests (#131).


## 2025-07-03

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.6.0`](#ssi---v160)

---

#### `ssi` - `v1.6.0`

 - **FEAT**: implement revocation verifier (#125).

## 1.6.0

 - **FEAT**: implement revocation verifier (#125).


## 2025-07-02

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.5.0`](#ssi---v150)

---

#### `ssi` - `v1.5.0`

 - **FEAT**: add multikeys secp256k1 p256 p384 p521 (#124).

## 1.5.0

 - **FEAT**: add multikeys secp256k1 p256 p384 p521 (#124).


## 2025-07-01

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.4.0`](#ssi---v140)

---

#### `ssi` - `v1.4.0`

 - **FEAT**: integrate dart_jsonwebtoken for JWT handling in DidVerifier (#113).

## 1.4.0

 - **FEAT**: integrate dart_jsonwebtoken for JWT handling in DidVerifier (#113).


## 2025-06-27

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.3.1`](#ssi---v131)

---

#### `ssi` - `v1.3.1`

 - **FIX**: update revocation status toJson (#123).

## 1.3.1

 - **FIX**: update revocation status toJson (#123).


## 2025-06-25

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.3.0`](#ssi---v130)

---

#### `ssi` - `v1.3.0`

 - **FEAT**: add revocation missing fields (#118).

## 1.3.0

 - **FEAT**: add revocation missing fields (#118).


## 2025-06-25

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.2.3`](#ssi---v123)

---

#### `ssi` - `v1.2.3`

 - **FIX**: working on update dh related part for the ed25519 (#121).

## 1.2.3

 - **FIX**: working on update dh related part for the ed25519 (#121).


## 2025-06-23

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.2.2`](#ssi---v122)

---

#### `ssi` - `v1.2.2`

 - **FIX**: use uint8list consistently (#119).

## 1.2.2

 - **FIX**: use uint8list consistently (#119).


## 2025-06-16

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.2.1`](#ssi---v121)

---

#### `ssi` - `v1.2.1`

 - **FIX**: add dh shared secret to secp256k1 (#109).

## 1.2.1

 - **FIX**: add dh shared secret to secp256k1 (#109).


## 2025-06-10

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.2.0`](#ssi---v120)

---

#### `ssi` - `v1.2.0`

 - **FEAT**: enhance proof verification with new data integrity suites (#112).

## 1.2.0

 - **FEAT**: enhance proof verification with new data integrity suites (#112).


## 2025-06-06

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.1.0`](#ssi---v110)

---

#### `ssi` - `v1.1.0`

 - **FEAT**: add tryParse/tryDecode methods (#111).

## 1.1.0

 - **FEAT**: add tryParse/tryDecode methods (#111).


## 2025-05-20

### Changes

---

Packages with breaking changes:

 - [`ssi` - `v1.0.0`](#ssi---v100)

Packages with other changes:

 - There are no other changes in this release.

Packages graduated to a stable release (see pre-releases prior to the stable version for changelog entries):

 - `ssi` - `v1.0.0`

---

#### `ssi` - `v1.0.0`

## 1.0.0

 - Graduate package to a stable release. See pre-releases prior to this version for changelog entries.


## 2025-05-15

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.29`](#ssi---v100-dev29)

---

#### `ssi` - `v1.0.0-dev.29`

 - **FEAT**: stateless HD wallets (#102).

## 1.0.0-dev.29

 - **FEAT**: stateless HD wallets (#102).


## 2025-05-14

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.28`](#ssi---v100-dev28)

---

#### `ssi` - `v1.0.0-dev.28`

 - **FIX**: dependency version conflict (#107).

## 1.0.0-dev.28

 - **FIX**: dependency version conflict (#107).


## 2025-05-13

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.27`](#ssi---v100-dev27)

---

#### `ssi` - `v1.0.0-dev.27`

 - **FIX**: added dependency_overrides for pointycastle (#104).

## 1.0.0-dev.27

 - **FIX**: added dependency_overrides for pointycastle (#104).


## 2025-05-07

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.25`](#ssi---v100-dev25)

---

#### `ssi` - `v1.0.0-dev.25`

 - **FIX**: version updated (#105).

## 1.0.0-dev.25

 - **FIX**: version updated (#105).


## 2025-05-07

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.23`](#ssi---v100-dev23)

---

#### `ssi` - `v1.0.0-dev.23`

 - **FIX**: pub.dev scoring related issues fixed (#103).

## 1.0.0-dev.23

 - **FIX**: pub.dev scoring related issues fixed (#103).


## 2025-05-05

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.22`](#ssi---v100-dev22)

---

#### `ssi` - `v1.0.0-dev.22`

 - **FEAT**: expose getKeyPair (#101).

## 1.0.0-dev.22

 - **FEAT**: expose getKeyPair (#101).


## 2025-04-30

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.21`](#ssi---v100-dev21)

---

#### `ssi` - `v1.0.0-dev.21`

 - **FIX**: issue reporting link (#98).

## 1.0.0-dev.21

 - **FIX**: issue reporting link (#98).


## 2025-04-30

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.20`](#ssi---v100-dev20)

---

#### `ssi` - `v1.0.0-dev.20`

 - **REFACTOR**: refactor code snippets (#72).
 - **FIX**: test concurrency (#36).
 - **FIX**: organize exports from across the credentials code (#86).
 - **FIX**: rename GenericWallet to PersistentWallet (#85).
 - **FIX**: making the interface of issue methods uniform (#83).
 - **FIX**: making the interface of issue methods uniform.
 - **FIX**: Adding VP tests (#65).
 - **FIX**: VP structure updated to be same as VC (#54).
 - **FIX**: remove affinidi links.
 - **FIX**: package publish (#46).
 - **FIX**: apply dart_flutter_team_lints rules to credentials (#42).
 - **FIX**: added support for meta package version 1.15.0 (#31).
 - **FEAT**: wallet key id abstraction (#68).
 - **FEAT**: restructure code snippets (#87).
 - **FEAT**: adding docs for presentation (#80).
 - **FEAT**: add credentials directory docs (#67).
 - **FEAT**: Replaced dynamic types with strict models in DidDocument (#78).
 - **FEAT**: Standardize VC fields (#66).
 - **FEAT**: checking kid related to issuer did (#64).
 - **FEAT**: cover public api members documentation for presentations (#58).
 - **FEAT**: encrypt from wallet (#61).
 - **FEAT**: implement LD V2 suite.
 - **FEAT**: generic wallet (#56).
 - **FEAT**: add support to issue VC as SdJwt (#52).
 - **FEAT**: add support for encrypt and decrypt on existing KeyPairs (#53).
 - **FEAT**: adding docs for model, suits and proofs (#90).
 - **FEAT**: p256 algorithm key pair (#49).
 - **FEAT**: refactor VC models.
 - **FEAT**: adding docs for model under /credential (#84).
 - **FEAT**: create tickets from TODOs (#50).
 - **FEAT**: move AWS KMS wallet under package (#30).
 - **FEAT**: add cache for document loader (#48).
 - **FEAT**: parsed vcs are read only (#47).
 - **FEAT**: implement verification service for VC (#35).
 - **FEAT**: add VP common interface (#29).
 - **FEAT**: extend support for embedded proof properties (#69).
 - **FEAT**: create a shared retry generator (#76).
 - **FEAT**: only return private key on generation (#77).
 - **FEAT**: Tests added for VC DM v1 and v2. (#71).
 - **FEAT**: sdjwt integrity verification (#51).
 - **DOCS**: update readme (#63).
 - **DOCS**: add code documentation for lib/src/credentials public members (#45).

## 1.0.0-dev.20

 - **REFACTOR**: refactor code snippets (#72).
 - **FIX**: test concurrency (#36).
 - **FIX**: organize exports from across the credentials code (#86).
 - **FIX**: rename GenericWallet to PersistentWallet (#85).
 - **FIX**: making the interface of issue methods uniform (#83).
 - **FIX**: making the interface of issue methods uniform.
 - **FIX**: Adding VP tests (#65).
 - **FIX**: VP structure updated to be same as VC (#54).
 - **FIX**: remove affinidi links.
 - **FIX**: package publish (#46).
 - **FIX**: apply dart_flutter_team_lints rules to credentials (#42).
 - **FIX**: added support for meta package version 1.15.0 (#31).
 - **FEAT**: wallet key id abstraction (#68).
 - **FEAT**: restructure code snippets (#87).
 - **FEAT**: adding docs for presentation (#80).
 - **FEAT**: add credentials directory docs (#67).
 - **FEAT**: Replaced dynamic types with strict models in DidDocument (#78).
 - **FEAT**: Standardize VC fields (#66).
 - **FEAT**: checking kid related to issuer did (#64).
 - **FEAT**: cover public api members documentation for presentations (#58).
 - **FEAT**: encrypt from wallet (#61).
 - **FEAT**: implement LD V2 suite.
 - **FEAT**: generic wallet (#56).
 - **FEAT**: add support to issue VC as SdJwt (#52).
 - **FEAT**: add support for encrypt and decrypt on existing KeyPairs (#53).
 - **FEAT**: adding docs for model, suits and proofs (#90).
 - **FEAT**: p256 algorithm key pair (#49).
 - **FEAT**: refactor VC models.
 - **FEAT**: adding docs for model under /credential (#84).
 - **FEAT**: create tickets from TODOs (#50).
 - **FEAT**: move AWS KMS wallet under package (#30).
 - **FEAT**: add cache for document loader (#48).
 - **FEAT**: parsed vcs are read only (#47).
 - **FEAT**: implement verification service for VC (#35).
 - **FEAT**: add VP common interface (#29).
 - **FEAT**: extend support for embedded proof properties (#69).
 - **FEAT**: create a shared retry generator (#76).
 - **FEAT**: only return private key on generation (#77).
 - **FEAT**: Tests added for VC DM v1 and v2. (#71).
 - **FEAT**: sdjwt integrity verification (#51).
 - **DOCS**: update readme (#63).
 - **DOCS**: add code documentation for lib/src/credentials public members (#45).


## 2025-04-09

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.19`](#ssi---v100-dev19)

---

#### `ssi` - `v1.0.0-dev.19`

 - **FIX**: export did document (#34).

## 1.0.0-dev.19

 - **FIX**: export did document (#34).


## 2025-04-08

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.18`](#ssi---v100-dev18)

---

#### `ssi` - `v1.0.0-dev.18`

 - **FEAT**: LDP VC Sign.

## 1.0.0-dev.18

 - **FEAT**: LDP VC Sign.


## 2025-04-08

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.17`](#ssi---v100-dev17)

---

#### `ssi` - `v1.0.0-dev.17`

 - **FIX**: wrong name for secp256 k 1 (#28).

## 1.0.0-dev.17

 - **FIX**: wrong name for secp256 k 1 (#28).


## 2025-04-07

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.16`](#ssi---v100-dev16)

---

#### `ssi` - `v1.0.0-dev.16`

 - **FEAT**: consolidate algo names (#23).

## 1.0.0-dev.16

 - **FEAT**: consolidate algo names (#23).


## 2025-04-04

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.15`](#ssi---v100-dev15)

---

#### `ssi` - `v1.0.0-dev.15`

 - **FEAT**: validate AWS KMS wallet support (#13).

## 1.0.0-dev.15

 - **FEAT**: validate AWS KMS wallet support (#13).


## 2025-04-04

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.14`](#ssi---v100-dev14)

---

#### `ssi` - `v1.0.0-dev.14`

 - **FEAT**: lower dart supported version to 3.6.0 (#20).

## 1.0.0-dev.14

 - **FEAT**: lower dart supported version to 3.6.0 (#20).


## 2025-04-03

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.13`](#ssi---v100-dev13)

---

#### `ssi` - `v1.0.0-dev.13`

 - **FEAT**: Remove privateKey from KeyPair interface (#21).

## 1.0.0-dev.13

 - **FEAT**: Remove privateKey from KeyPair interface (#21).


## 2025-04-03

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.12`](#ssi---v100-dev12)

---

#### `ssi` - `v1.0.0-dev.12`

 - **FIX**: workflow.

## 1.0.0-dev.12

 - **FIX**: workflow.


## 2025-04-03

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.11`](#ssi---v100-dev11)

---

#### `ssi` - `v1.0.0-dev.11`

 - **FIX**: cut new release & fix workflow name.

## 1.0.0-dev.11

 - **FIX**: cut new release & fix workflow name.


## 2025-04-03

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.10`](#ssi---v100-dev10)

---

#### `ssi` - `v1.0.0-dev.10`

 - **FEAT**: DID handling refactoring (#11).


## 2025-04-02

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.10`](#ssi---v100-dev10)

---

#### `ssi` - `v1.0.0-dev.10`

 - **FEAT**: DID handling refactoring (#11).

## 1.0.0-dev.10

 - **FEAT**: DID handling refactoring (#11).


## 2025-04-02

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.9`](#ssi---v100-dev9)

---

#### `ssi` - `v1.0.0-dev.9`

 - **FIX**: checks ci reference (#18).
 - **FIX**: linting and  packaging issues (#5).
 - **FIX**: implement did.
 - **FIX**: signature scheme (#2).
 - **FIX**: format.
 - **FEAT**: name package & setup ci (#14).
 - **FEAT**: VC interfaces.
 - **FEAT**: add base resolution and did web (#8).
 - **FEAT**: add edward curve add did peer (#7).

## 1.0.0-dev.9

 - **FIX**: checks ci reference (#18).
 - **FIX**: linting and  packaging issues (#5).
 - **FIX**: implement did.
 - **FIX**: signature scheme (#2).
 - **FIX**: format.
 - **FEAT**: name package & setup ci (#14).
 - **FEAT**: VC interfaces.
 - **FEAT**: add base resolution and did web (#8).
 - **FEAT**: add edward curve add did peer (#7).


## 2025-04-01

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.8`](#ssi---v100-dev8)

---

#### `ssi` - `v1.0.0-dev.8`

 - **FEAT**: VC interfaces.

## 1.0.0-dev.8

 - **FEAT**: VC interfaces.


## 2025-03-28

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.7`](#ssi---v100-dev7)

---

#### `ssi` - `v1.0.0-dev.7`

 - **FEAT**: add base resolution and did web (#8).

## 1.0.0-dev.7

 - **FEAT**: add base resolution and did web (#8).


## 2025-03-28

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.6`](#ssi---v100-dev6)

---

#### `ssi` - `v1.0.0-dev.6`

 - **FEAT**: add edward curve add did peer (#7).

## 1.0.0-dev.6

 - **FEAT**: add edward curve add did peer (#7).


## 2025-03-26

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.5`](#ssi---v100-dev5)

---

#### `ssi` - `v1.0.0-dev.5`

 - **FIX**: linting and  packaging issues (#5).
 - **FIX**: implement did.
 - **FIX**: signature scheme (#2).
 - **FIX**: format.

## 1.0.0-dev.5

 - **FIX**: linting and  packaging issues (#5).
 - **FIX**: implement did.
 - **FIX**: signature scheme (#2).
 - **FIX**: format.


## 2025-03-21

### Changes

---

Packages with breaking changes:

 - There are no breaking changes in this release.

Packages with other changes:

 - [`ssi` - `v1.0.0-dev.4`](#ssi---v100-dev4)

---

#### `ssi` - `v1.0.0-dev.4`

 - **FIX**: format.

## 1.0.0-dev.4

 - **FIX**: format.

# 1.0.0-dev.3
- ignored .failed_tracker
- ignored .failed_tracker
- fix: format
- ci: add simple ci check
- chore: migrate
- Initial commit

# 1.0.0-dev.2
- ignored .failed_tracker
- fix: format
- ci: add simple ci check
- chore: migrate
- Initial commit
