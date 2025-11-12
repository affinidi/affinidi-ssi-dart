import 'dart:convert';
import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_verifier.dart';
import '../../did/public_key_utils.dart';
import '../../digest_utils.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import 'embedded_proof_suite.dart';

/// Base class for Data Integrity proof verifiers.
abstract class BaseDataIntegrityVerifier extends EmbeddedProofSuiteVerifyOptions
    implements EmbeddedProofVerifier {
  /// The DID of the issuer.
  final String issuerDid;

  /// Function to get the current time.
  final DateTime Function() getNow;

  /// Optional domain restriction.
  final List<String>? domain;

  /// Optional challenge value.
  final String? challenge;

  /// Creates a new BaseDataIntegrityVerifier.
  BaseDataIntegrityVerifier({
    required this.issuerDid,
    this.getNow = DateTime.now,
    this.domain,
    this.challenge,
    super.customDocumentLoader,
  });

  /// The expected proof type.
  String get expectedProofType;

  /// The expected cryptographic suite.
  String get expectedCryptosuite;

  /// The context URL for this proof type.
  String get contextUrl;

  /// The field name containing the proof value.
  String get proofValueField;

  @override
  Future<VerificationResult> verify(Map<String, dynamic> document,
      {DateTime Function() getNow = DateTime.now}) async {
    final copy = Map.of(document);
    final proof = copy.remove('proof');

    final validationResult = _validateProofStructure(proof);
    if (!validationResult.isValid) {
      return validationResult;
    }

    final expiryResult = _validateExpiry(proof, getNow());
    if (!expiryResult.isValid) {
      return expiryResult;
    }

    // Subclasses handle cryptosuite-specific validation
    final cryptosuiteValidationResult =
        await validateCryptosuite(document, proof);
    if (!cryptosuiteValidationResult.isValid) {
      return cryptosuiteValidationResult;
    }

    final Uri verificationMethod;
    try {
      verificationMethod = Uri.parse(proof['verificationMethod'] as String);
    } catch (e) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof.verificationMethod'],
      );
    }

    final vmDid = verificationMethod.toString().split('#').first;
    if (vmDid != issuerDid) {
      return VerificationResult.invalid(
        errors: ['issuer DID does not match proof.verificationMethod DID'],
      );
    }

    final originalProofValue = proof.remove(proofValueField);
    if (originalProofValue == null) {
      return VerificationResult.invalid(
        errors: ['missing $proofValueField'],
      );
    }

    // Prepare proof for verification (subclasses handle cryptosuite-specific preparation)
    final proofForVerification = prepareProofForVerification(proof, document);

    final cacheLoadDocument = _cacheLoadDocument(customDocumentLoader);
    final hash = await computeSignatureHash(
        proofForVerification, copy, cacheLoadDocument);
    final isValid = await verifySignature(
        originalProofValue as String, issuerDid, verificationMethod, hash);

    if (!isValid) {
      return VerificationResult.invalid(
        errors: ['signature invalid'],
      );
    }

    return VerificationResult.ok();
  }

  /// Computes the signature hash from proof and document.
  Future<Uint8List> computeSignatureHash(
    Map<String, dynamic> proof,
    Map<String, dynamic> unsignedCredential,
    Future<RemoteDocument?> Function(Uri url, LoadDocumentOptions? options)
        documentLoader,
  );

  /// Verifies the signature against the computed hash.
  Future<bool> verifySignature(
    String proofValue,
    String issuerDid,
    Uri verificationMethod,
    Uint8List hash,
  );

  VerificationResult _validateProofStructure(dynamic proof) {
    if (proof == null || proof is! Map<String, dynamic>) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof'],
      );
    }

    if (proof['type'] != expectedProofType) {
      return VerificationResult.invalid(
        errors: ['invalid proof type, expected $expectedProofType'],
      );
    }

    final cryptosuite = proof['cryptosuite'];
    if (cryptosuite != null && cryptosuite != expectedCryptosuite) {
      return VerificationResult.invalid(
        errors: ['invalid cryptosuite, expected $expectedCryptosuite'],
      );
    }

    return VerificationResult.ok();
  }

  VerificationResult _validateExpiry(Map<String, dynamic> proof, DateTime now) {
    final expires = proof['expires'];
    if (expires != null) {
      DateTime expiryDate;
      if (expires is String) {
        try {
          expiryDate = DateTime.parse(expires);
        } catch (e) {
          return VerificationResult.invalid(
            errors: ['invalid expires format'],
          );
        }
      } else if (expires is DateTime) {
        expiryDate = expires;
      } else {
        return VerificationResult.invalid(
          errors: ['invalid expires type'],
        );
      }

      if (now.isAfter(expiryDate)) {
        return VerificationResult.invalid(errors: ['proof has expired']);
      }
    }
    return VerificationResult.ok();
  }

  /// Validates cryptosuite-specific requirements.
  ///
  /// Subclasses override this method to implement cryptosuite-specific validation logic.
  /// Base implementation performs no additional validation.
  Future<VerificationResult> validateCryptosuite(
      Map<String, dynamic> document, Map<String, dynamic> proof) async {
    return VerificationResult.ok();
  }

  /// Prepares proof structure for verification according to cryptosuite requirements.
  ///
  /// Subclasses override this method to implement cryptosuite-specific proof preparation.
  /// Base implementation uses standard data integrity context.
  Map<String, dynamic> prepareProofForVerification(
      Map<String, dynamic> proof, Map<String, dynamic> document) {
    final proofCopy = Map<String, dynamic>.from(proof);
    proofCopy['@context'] = contextUrl;
    return proofCopy;
  }
}

/// Computes Data Integrity hash from proof and document.
Future<Uint8List> computeDataIntegrityHash(
  Map<String, dynamic> proof,
  Map<String, dynamic> unsignedCredential,
  Future<RemoteDocument?> Function(Uri url, LoadDocumentOptions? options)
      documentLoader,
) async {
  final normalizedProof = await JsonLdProcessor.normalize(
    proof,
    options: JsonLdOptions(
      safeMode: true,
      documentLoader: documentLoader,
    ),
  );
  final proofConfigHash = DigestUtils.getDigest(
    utf8.encode(normalizedProof),
    hashingAlgorithm: HashingAlgorithm.sha256,
  );

  final normalizedContent = await JsonLdProcessor.normalize(
    unsignedCredential,
    options: JsonLdOptions(
      safeMode: true,
      documentLoader: documentLoader,
    ),
  );
  final transformedDocumentHash = DigestUtils.getDigest(
    utf8.encode(normalizedContent),
    hashingAlgorithm: HashingAlgorithm.sha256,
  );

  return Uint8List.fromList(proofConfigHash + transformedDocumentHash);
}

/// Verifies a Data Integrity signature.
Future<bool> verifyDataIntegritySignature(
  String proofValue,
  String issuerDid,
  Uri verificationMethod,
  Uint8List hash,
  String cryptosuite,
) async {
  final signature = multiBaseToUint8List(proofValue);

  final expectedSchemes = cryptosuiteToScheme[cryptosuite];
  if (expectedSchemes == null || expectedSchemes.isEmpty) {
    throw SsiException(
      message:
          'Unknown cryptosuite: $cryptosuite, cannot determine signature scheme.',
      code: SsiExceptionType.unsupportedSignatureScheme.code,
    );
  }

  // For single-scheme cryptosuites, use the only scheme
  // For multi-scheme cryptosuites, this should be handled by specialized verifiers
  final expectedScheme = expectedSchemes.first;

  final verifier = await DidVerifier.create(
    algorithm: expectedScheme,
    kid: verificationMethod.toString(),
    issuerDid: issuerDid,
  );
  return verifier.verify(hash, signature);
}

/// Document loader function type.
typedef LibDocumentLoader = Future<RemoteDocument> Function(
  Uri url,
  LoadDocumentOptions? options,
);

LibDocumentLoader _cacheLoadDocument(
  DocumentLoader customLoader,
) =>
    (Uri url, LoadDocumentOptions? options) async {
      final fromCache = _documentCache[url];
      if (fromCache != null) {
        return Future.value(fromCache);
      }

      final custom = await customLoader(url);
      if (custom != null) {
        return Future.value(RemoteDocument(document: custom));
      }

      return loadDocument(url, options);
    };

/// Creates a cached document loader.
LibDocumentLoader createCacheDocumentLoader(
  DocumentLoader customLoader,
) =>
    _cacheLoadDocument(customLoader);

final _documentCache = <Uri, RemoteDocument>{
  Uri.parse('https://w3id.org/security/data-integrity/v1'): RemoteDocument(
    document: jsonDecode(r'''
{
  "@context": {
    "id": "@id",
    "type": "@type",
    "@protected": true,
    "proof": {
      "@id": "https://w3id.org/security#proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "cryptosuite": "https://w3id.org/security#cryptosuite",
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}
 '''),
  ),
  Uri.parse('https://w3id.org/security/v2'): RemoteDocument(
    document: jsonDecode(r'''
{
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "AesKeyWrappingKey2019": "sec:AesKeyWrappingKey2019",
    "DeleteKeyOperation": "sec:DeleteKeyOperation",
    "DeriveSecretOperation": "sec:DeriveSecretOperation",
    "EcdsaSecp256k1Signature2019": "sec:EcdsaSecp256k1Signature2019",
    "EcdsaSecp256r1Signature2019": "sec:EcdsaSecp256r1Signature2019",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "EcdsaSecp256r1VerificationKey2019": "sec:EcdsaSecp256r1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "EquihashProof2018": "sec:EquihashProof2018",
    "ExportKeyOperation": "sec:ExportKeyOperation",
    "GenerateKeyOperation": "sec:GenerateKeyOperation",
    "KmsOperation": "sec:KmsOperation",
    "RevokeKeyOperation": "sec:RevokeKeyOperation",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "Sha256HmacKey2019": "sec:Sha256HmacKey2019",
    "SignOperation": "sec:SignOperation",
    "UnwrapKeyOperation": "sec:UnwrapKeyOperation",
    "VerifyOperation": "sec:VerifyOperation",
    "WrapKeyOperation": "sec:WrapKeyOperation",
    "X25519KeyAgreementKey2019": "sec:X25519KeyAgreementKey2019",

    "allowedAction": "sec:allowedAction",
    "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
    "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"},
    "capability": {"@id": "sec:capability", "@type": "@id"},
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {"@id": "sec:capabilityChain", "@type": "@id", "@container": "@list"},
    "capabilityDelegation": {"@id": "sec:capabilityDelegationMethod", "@type": "@id", "@container": "@set"},
    "capabilityInvocation": {"@id": "sec:capabilityInvocationMethod", "@type": "@id", "@container": "@set"},
    "caveat": {"@id": "sec:caveat", "@type": "@id", "@container": "@set"},
    "challenge": "sec:challenge",
    "ciphertext": "sec:ciphertext",
    "controller": {"@id": "sec:controller", "@type": "@id"},
    "delegator": {"@id": "sec:delegator", "@type": "@id"},
    "equihashParameterK": {"@id": "sec:equihashParameterK", "@type": "xsd:integer"},
    "equihashParameterN": {"@id": "sec:equihashParameterN", "@type": "xsd:integer"},
    "invocationTarget": {"@id": "sec:invocationTarget", "@type": "@id"},
    "invoker": {"@id": "sec:invoker", "@type": "@id"},
    "jws": "sec:jws",
    "keyAgreement": {"@id": "sec:keyAgreementMethod", "@type": "@id", "@container": "@set"},
    "kmsModule": {"@id": "sec:kmsModule"},
    "parentCapability": {"@id": "sec:parentCapability", "@type": "@id"},
    "plaintext": "sec:plaintext",
    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"},
    "proofValue": "sec:proofValue",
    "referenceId": "sec:referenceId",
    "unwrappedKey": "sec:unwrappedKey",
    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"},
    "verifyData": "sec:verifyData",
    "wrappedKey": "sec:wrappedKey"
  }]
}
'''),
  ),
  Uri.parse('https://w3id.org/security/data-integrity/v2'): RemoteDocument(
    document: jsonDecode(r'''
{
  "@context": {
    "id": "@id",
    "type": "@type",
    "@protected": true,
    "proof": {
      "@id": "https://w3id.org/security#proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "previousProof": {
          "@id": "https://w3id.org/security#previousProof",
          "@type": "@id"
        },
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "cryptosuite": {
          "@id": "https://w3id.org/security#cryptosuite",
          "@type": "https://w3id.org/security#cryptosuiteString"
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}
 '''),
  ),
  Uri.parse('https://www.w3.org/2018/credentials/v1'): RemoteDocument(
    document: jsonDecode(r'''
{
  "@context": {
    "@version": 1.1,
    "@protected": true,

    "id": "@id",
    "type": "@type",

    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "credentialSchema": {
          "@id": "cred:credentialSchema",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "JsonSchemaValidator2018": "cred:JsonSchemaValidator2018"
          }
        },
        "credentialStatus": {"@id": "cred:credentialStatus", "@type": "@id"},
        "credentialSubject": {"@id": "cred:credentialSubject", "@type": "@id"},
        "evidence": {"@id": "cred:evidence", "@type": "@id"},
        "expirationDate": {"@id": "cred:expirationDate", "@type": "xsd:dateTime"},
        "holder": {"@id": "cred:holder", "@type": "@id"},
        "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
        "issuer": {"@id": "cred:issuer", "@type": "@id"},
        "issuanceDate": {"@id": "cred:issuanceDate", "@type": "xsd:dateTime"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "refreshService": {
          "@id": "cred:refreshService",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "ManualRefreshService2018": "cred:ManualRefreshService2018"
          }
        },
        "termsOfUse": {"@id": "cred:termsOfUse", "@type": "@id"},
        "validFrom": {"@id": "cred:validFrom", "@type": "xsd:dateTime"},
        "validUntil": {"@id": "cred:validUntil", "@type": "xsd:dateTime"}
      }
    },

    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",

        "holder": {"@id": "cred:holder", "@type": "@id"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "verifiableCredential": {"@id": "cred:verifiableCredential", "@type": "@id", "@container": "@graph"}
      }
    },

    "EcdsaSecp256k1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "EcdsaSecp256r1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "Ed25519Signature2018": {
      "@id": "https://w3id.org/security#Ed25519Signature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "RsaSignature2018": {
      "@id": "https://w3id.org/security#RsaSignature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "proof": {"@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph"}
  }
}
'''),
  ),
  Uri.parse('https://www.w3.org/ns/credentials/v2'): RemoteDocument(
    document: jsonDecode(r'''
{
  "@context": {
    "@protected": true,

    "id": "@id",
    "type": "@type",

    "description": "https://schema.org/description",
    "digestMultibase": {
      "@id": "https://w3id.org/security#digestMultibase",
      "@type": "https://w3id.org/security#multibase"
    },
    "digestSRI": {
      "@id": "https://www.w3.org/2018/credentials#digestSRI",
      "@type": "https://www.w3.org/2018/credentials#sriString"
    },
    "mediaType": {
      "@id": "https://schema.org/encodingFormat"
    },
    "name": "https://schema.org/name",

    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "confidenceMethod": {
          "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
          "@type": "@id"
        },
        "credentialSchema": {
          "@id": "https://www.w3.org/2018/credentials#credentialSchema",
          "@type": "@id"
        },
        "credentialStatus": {
          "@id": "https://www.w3.org/2018/credentials#credentialStatus",
          "@type": "@id"
        },
        "credentialSubject": {
          "@id": "https://www.w3.org/2018/credentials#credentialSubject",
          "@type": "@id"
        },
        "description": "https://schema.org/description",
        "evidence": {
          "@id": "https://www.w3.org/2018/credentials#evidence",
          "@type": "@id"
        },
        "issuer": {
          "@id": "https://www.w3.org/2018/credentials#issuer",
          "@type": "@id"
        },
        "name": "https://schema.org/name",
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@type": "@id",
          "@container": "@graph"
        },
        "refreshService": {
          "@id": "https://www.w3.org/2018/credentials#refreshService",
          "@type": "@id"
        },
        "relatedResource": {
          "@id": "https://www.w3.org/2018/credentials#relatedResource",
          "@type": "@id"
        },
        "renderMethod": {
          "@id": "https://www.w3.org/2018/credentials#renderMethod",
          "@type": "@id"
        },
        "termsOfUse": {
          "@id": "https://www.w3.org/2018/credentials#termsOfUse",
          "@type": "@id"
        },
        "validFrom": {
          "@id": "https://www.w3.org/2018/credentials#validFrom",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "validUntil": {
          "@id": "https://www.w3.org/2018/credentials#validUntil",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        }
      }
    },

    "EnvelopedVerifiableCredential":
      "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",

    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "holder": {
          "@id": "https://www.w3.org/2018/credentials#holder",
          "@type": "@id"
        },
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@type": "@id",
          "@container": "@graph"
        },
        "termsOfUse": {
          "@id": "https://www.w3.org/2018/credentials#termsOfUse",
          "@type": "@id"
        },
        "verifiableCredential": {
          "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
          "@type": "@id",
          "@container": "@graph",
          "@context": null
        }
      }
    },

    "EnvelopedVerifiablePresentation":
      "https://www.w3.org/2018/credentials#EnvelopedVerifiablePresentation",

    "JsonSchemaCredential":
      "https://www.w3.org/2018/credentials#JsonSchemaCredential",

    "JsonSchema": {
      "@id": "https://www.w3.org/2018/credentials#JsonSchema",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "jsonSchema": {
          "@id": "https://www.w3.org/2018/credentials#jsonSchema",
          "@type": "@json"
        }
      }
    },

    "BitstringStatusListCredential":
      "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",

    "BitstringStatusList": {
      "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusList",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "encodedList": {
          "@id": "https://www.w3.org/ns/credentials/status#encodedList",
          "@type": "https://w3id.org/security#multibase"
        },
        "statusPurpose":
          "https://www.w3.org/ns/credentials/status#statusPurpose",
        "ttl": "https://www.w3.org/ns/credentials/status#ttl"
      }
    },

    "BitstringStatusListEntry": {
      "@id":
        "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "statusListCredential": {
          "@id":
            "https://www.w3.org/ns/credentials/status#statusListCredential",
          "@type": "@id"
        },
        "statusListIndex":
          "https://www.w3.org/ns/credentials/status#statusListIndex",
        "statusPurpose":
          "https://www.w3.org/ns/credentials/status#statusPurpose",
        "statusMessage": {
          "@id": "https://www.w3.org/ns/credentials/status#statusMessage",
          "@context": {
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "message": "https://www.w3.org/ns/credentials/status#message",
            "status": "https://www.w3.org/ns/credentials/status#status"
          }
        },
        "statusReference": {
          "@id": "https://www.w3.org/ns/credentials/status#statusReference",
          "@type": "@id"
        },
        "statusSize": {
          "@id": "https://www.w3.org/ns/credentials/status#statusSize",
          "@type": "https://www.w3.org/2001/XMLSchema#integer"
        }
      }
    },

    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "cryptosuite": {
          "@id": "https://w3id.org/security#cryptosuite",
          "@type": "https://w3id.org/security#cryptosuiteString"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "previousProof": {
          "@id": "https://w3id.org/security#previousProof",
          "@type": "@id"
        },
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    },

    "...": {
      "@id": "https://www.iana.org/assignments/jwt#..."
    },
    "_sd": {
      "@id": "https://www.iana.org/assignments/jwt#_sd",
      "@type": "@json"
    },
    "_sd_alg": {
      "@id": "https://www.iana.org/assignments/jwt#_sd_alg"
    },
    "aud": {
      "@id": "https://www.iana.org/assignments/jwt#aud",
      "@type": "@id"
    },
    "cnf": {
      "@id": "https://www.iana.org/assignments/jwt#cnf",
      "@context": {
        "@protected": true,

        "kid": {
          "@id": "https://www.iana.org/assignments/jwt#kid",
          "@type": "@id"
        },
        "jwk": {
          "@id": "https://www.iana.org/assignments/jwt#jwk",
          "@type": "@json"
        }
      }
    },
    "exp": {
      "@id": "https://www.iana.org/assignments/jwt#exp",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "iat": {
      "@id": "https://www.iana.org/assignments/jwt#iat",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "iss": {
      "@id": "https://www.iana.org/assignments/jose#iss",
      "@type": "@id"
    },
    "jku": {
      "@id": "https://www.iana.org/assignments/jose#jku",
      "@type": "@id"
    },
    "kid": {
      "@id": "https://www.iana.org/assignments/jose#kid",
      "@type": "@id"
    },
    "nbf": {
      "@id": "https://www.iana.org/assignments/jwt#nbf",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "sub": {
      "@id": "https://www.iana.org/assignments/jose#sub",
      "@type": "@id"
    },
    "x5u": {
      "@id": "https://www.iana.org/assignments/jose#x5u",
      "@type": "@id"
    }
  }
}
'''),
  ),
};
