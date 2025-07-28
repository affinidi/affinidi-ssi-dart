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

    // JCS cryptosuites require context validation per specs
    if (_isJcsCryptosuite(expectedCryptosuite)) {
      final contextValidationResult = _validateJcsContext(document, proof);
      if (!contextValidationResult.isValid) {
        return contextValidationResult;
      }
    }

    final Uri verificationMethod;
    try {
      verificationMethod = Uri.parse(proof['verificationMethod'] as String);
    } catch (e) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof.verificationMethod'],
      );
    }

    final originalProofValue = proof.remove(proofValueField);
    if (originalProofValue == null) {
      return VerificationResult.invalid(
        errors: ['missing $proofValueField'],
      );
    }

    // Prepare proof for verification
    final proofForVerification = _prepareProofForVerification(proof, document);

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

  /// Validates context for JCS cryptosuites.
  ///
  /// Ensures that the document context starts with all values from the proof context
  /// in the same order, as required by the JCS specification.
  VerificationResult _validateJcsContext(
      Map<String, dynamic> document, Map<String, dynamic> proof) {
    final proofContext = proof['@context'];
    if (proofContext != null) {
      final documentContext = document['@context'];
      if (!contextStartsWith(documentContext, proofContext)) {
        return VerificationResult.invalid(
          errors: [
            'document @context does not start with proof @context values in the same order'
          ],
        );
      }
    }
    return VerificationResult.ok();
  }

  /// Checks if the cryptosuite uses JCS canonicalization.
  bool _isJcsCryptosuite(String cryptosuite) {
    return cryptosuite.endsWith('-jcs-2019') ||
        cryptosuite.endsWith('-jcs-2022');
  }

  /// Prepares proof structure for verification according to cryptosuite requirements.
  Map<String, dynamic> _prepareProofForVerification(
      Map<String, dynamic> proof, Map<String, dynamic> document) {
    final proofCopy = Map<String, dynamic>.from(proof);

    if (_isJcsCryptosuite(expectedCryptosuite)) {
      // Use document context in proof for JCS cryptosuites during verification
      final documentContext = document['@context'];
      if (documentContext != null) {
        proofCopy['@context'] = documentContext;
      }

      // For JCS cryptosuites, we do NOT add null fields during verification
      // The proof should be verified exactly as it was signed
    } else {
      // For RDFC cryptosuites, use standard data integrity context
      proofCopy['@context'] = contextUrl;
    }

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

  final expectedScheme = cryptosuiteToScheme[cryptosuite];
  if (expectedScheme == null) {
    throw SsiException(
      message:
          'Unknown cryptosuite: $cryptosuite, cannot determine signature scheme.',
      code: SsiExceptionType.unsupportedSignatureScheme.code,
    );
  }

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

/// Checks if document context starts with proof context values in order.
/// Required for JCS cryptosuite context validation.
bool contextStartsWith(dynamic documentContext, dynamic proofContext) {
  // Convert both contexts to lists for comparison
  final List<dynamic> docList = _contextToList(documentContext);
  final List<dynamic> proofList = _contextToList(proofContext);

  // Check if document context starts with proof context values
  if (proofList.length > docList.length) return false;

  for (int i = 0; i < proofList.length; i++) {
    if (docList[i] != proofList[i]) return false;
  }

  return true;
}

/// Converts a context value to normalized list format for comparison.
List<dynamic> _contextToList(dynamic context) {
  if (context is List) {
    return context;
  } else if (context is String) {
    return [context];
  } else if (context is Map) {
    return [context];
  } else {
    return [];
  }
}

final _documentCache = <Uri, RemoteDocument>{
  Uri.parse('https://w3id.org/security/data-integrity/v1'): RemoteDocument(
    document: jsonDecode(r'''
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@version": 1.1,
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
            "@version": 1.1,
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
    "cryptosuite": "https://w3id.org/security#cryptosuite"
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
};
