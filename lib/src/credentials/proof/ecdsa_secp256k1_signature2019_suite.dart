import 'dart:convert';
import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_signer.dart';
import '../../util/base64_util.dart';
import 'base_secp256k1_verifier.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';

const _signatureType = 'EcdsaSecp256k1Signature2019';
const _securityContext = 'https://w3id.org/security/v2';

/// Generates Linked Data Proofs using the EcdsaSecp256k1Signature2019 signature suite.
///
/// Signs Verifiable Credentials by normalizing the credential and the proof separately,
/// hashing them, and then signing the combined hash using a [DidSigner].
class Secp256k1Signature2019Generator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  /// The DID signer used to produce the proof signature.
  final DidSigner signer;

  /// Constructs a new [Secp256k1Signature2019Generator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], and [domain] configure the proof metadata.
  Secp256k1Signature2019Generator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
  });

  /// Generates an [EmbeddedProof] for the given [document].
  @override
  Future<EmbeddedProof> generate(Map<String, dynamic> document) async {
    final created = DateTime.now();
    final proof = {
      '@context': _securityContext,
      'type': _signatureType,
      'created': created.toIso8601String(),
      'verificationMethod': signer.keyId,
      'proofPurpose': proofPurpose?.value,
      'expires': expires?.toIso8601String(),
      'challenge': challenge,
      'domain': domain,
    };

    document.remove('proof');

    final cacheLoadDocument = _cacheLoadDocument(customDocumentLoader);
    final jws = await computeVcHash(proof, document, cacheLoadDocument).then(
      (hash) => _computeJws(hash, signer),
    );

    proof.remove('@context');
    proof['jws'] = jws;

    return EcdsaSecp256k1Signature2019Proof(
        type: 'EcdsaSecp256k1Signature2019',
        created: created,
        verificationMethod: signer.keyId,
        proofPurpose: proofPurpose?.value,
        jws: jws,
        expires: expires,
        challenge: challenge,
        domain: domain);
  }

  static Future<String> _computeJws(
    Uint8List payloadToSign,
    DidSigner signer,
  ) async {
    final encodedHeader = base64UrlNoPadEncode(
      utf8.encode(
        jsonEncode(
          {
            'alg': 'ES256K',
            'b64': false,
            'crit': ['b64'],
          },
        ),
      ),
    );

    final jwsToSign = Uint8List.fromList(
      utf8.encode(encodedHeader) + utf8.encode('.') + payloadToSign,
    );

    final jws = base64UrlNoPadEncode(await signer.sign(jwsToSign));

    return '$encodedHeader..$jws';
  }

  static LibDocumentLoader _cacheLoadDocument(
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

  static final _documentCache = <Uri, RemoteDocument>{
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
    Uri.parse('https://w3id.org/security/v1'): RemoteDocument(
      document: jsonDecode(r'''
{
  "@context": {
    "id": "@id",
    "type": "@type",

    "dc": "http://purl.org/dc/terms/",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "EcdsaKoblitzSignature2016": "sec:EcdsaKoblitzSignature2016",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "EncryptedMessage": "sec:EncryptedMessage",
    "GraphSignature2012": "sec:GraphSignature2012",
    "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
    "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
    "CryptographicKey": "sec:Key",

    "authenticationTag": "sec:authenticationTag",
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "cipherAlgorithm": "sec:cipherAlgorithm",
    "cipherData": "sec:cipherData",
    "cipherKey": "sec:cipherKey",
    "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
    "creator": {"@id": "dc:creator", "@type": "@id"},
    "digestAlgorithm": "sec:digestAlgorithm",
    "digestValue": "sec:digestValue",
    "domain": "sec:domain",
    "encryptionKey": "sec:encryptionKey",
    "expiration": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "initializationVector": "sec:initializationVector",
    "iterationCount": "sec:iterationCount",
    "nonce": "sec:nonce",
    "normalizationAlgorithm": "sec:normalizationAlgorithm",
    "owner": {"@id": "sec:owner", "@type": "@id"},
    "password": "sec:password",
    "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
    "privateKeyPem": "sec:privateKeyPem",
    "publicKey": {"@id": "sec:publicKey", "@type": "@id"},
    "publicKeyBase58": "sec:publicKeyBase58",
    "publicKeyPem": "sec:publicKeyPem",
    "publicKeyWif": "sec:publicKeyWif",
    "publicKeyService": {"@id": "sec:publicKeyService", "@type": "@id"},
    "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
    "salt": "sec:salt",
    "signature": "sec:signature",
    "signatureAlgorithm": "sec:signingAlgorithm",
    "signatureValue": "sec:signatureValue"
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
                    "@container": "@graph",
                    "@context": "https://w3id.org/security/v2"
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
        "EnvelopedVerifiableCredential": "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",
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
        "EnvelopedVerifiablePresentation": "https://www.w3.org/2018/credentials#EnvelopedVerifiablePresentation",
        "JsonSchemaCredential": "https://www.w3.org/2018/credentials#JsonSchemaCredential"
    }
}
'''),
    ),
  };
}

/// Verifies Linked Data Proofs signed with the EcdsaSecp256k1Signature2019 signature suite.
///
/// Normalizes and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
class Secp256k1Signature2019Verifier extends BaseSecp256k1Verifier {
  /// Constructs a new [Secp256k1Signature2019Verifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  Secp256k1Signature2019Verifier({
    required super.issuerDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
  });

  @override
  String get expectedProofType => _signatureType;

  @override
  String get contextUrl => _securityContext;

  @override
  String get proofValueField => 'jws';

  @override
  Future<Uint8List> computeSignatureHash(
    Map<String, dynamic> proof,
    Map<String, dynamic> unsignedCredential,
    Future<RemoteDocument?> Function(Uri url, LoadDocumentOptions? options)
        documentLoader,
  ) async {
    return computeVcHash(proof, unsignedCredential, documentLoader);
  }

  @override
  Future<bool> verifySignature(
    String proofValue,
    String issuerDid,
    Uri verificationMethod,
    Uint8List hash,
  ) async {
    return verifyJws(proofValue, issuerDid, verificationMethod, hash);
  }
}

/// Data model representing a Linked Data Proof of type EcdsaSecp256k1Signature2019.
///
/// Contains signature metadata and the actual JWS signature.
class EcdsaSecp256k1Signature2019Proof extends EmbeddedProof {
  /// The JWS (JSON Web Signature) string that signs the normalized data.

  final String jws;

  /// Constructs a new [EcdsaSecp256k1Signature2019Proof].
  ///
  /// Required fields include [type], [created], [verificationMethod], [proofPurpose], and [jws].
  /// Optional fields include [expires], [challenge], and [domain].
  EcdsaSecp256k1Signature2019Proof(
      {required super.type,
      required super.created,
      required super.verificationMethod,
      required super.proofPurpose,
      required this.jws,
      super.expires,
      super.domain,
      super.challenge});

  @override
  Map<String, dynamic> toJson() {
    final json = super.toJson();
    json['jws'] = jws;
    return json;
  }
}
