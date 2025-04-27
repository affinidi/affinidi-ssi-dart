import 'dart:convert';
import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:pointycastle/api.dart';

import '../../did/did_signer.dart';
import '../../did/did_verifier.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../util/base64_util.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';

final _sha256 = Digest('SHA-256');

const _signatureType = 'EcdsaSecp256k1Signature2019';
const _securityContext = 'https://w3id.org/security/v2';

class Secp256k1Signature2019Generator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  final DidSigner signer;

  Secp256k1Signature2019Generator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
  });

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
    final jws = await _computeVcHash(proof, document, cacheLoadDocument).then(
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
}

class Secp256k1Signature2019Verifier extends EmbeddedProofSuiteVerifyOptions
    implements EmbeddedProofVerifier {
  final String issuerDid;
  final DateTime Function() getNow;
  final List<String>? domain;
  final String? challenge;

  Secp256k1Signature2019Verifier({
    required this.issuerDid,
    this.getNow = DateTime.now,
    this.domain,
    this.challenge,
    super.customDocumentLoader,
  });

  @override
  Future<VerificationResult> verify(Map<String, dynamic> document) async {
    final copy = Map.of(document);
    final proof = copy.remove('proof');

    if (proof == null || proof is! Map<String, dynamic>) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof'],
      );
    }

    Uri verificationMethod;
    try {
      verificationMethod = Uri.parse(proof['verificationMethod'] as String);
    } catch (e) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof.verificationMethod'],
      );
    }

    final originalJws = proof.remove('jws');
    proof['@context'] = _securityContext;

    final cacheLoadDocument = _cacheLoadDocument(customDocumentLoader);
    final hash = await _computeVcHash(proof, copy, cacheLoadDocument);
    final isValid = await _verifyJws(
        originalJws as String, issuerDid, verificationMethod, hash);

    if (!isValid) {
      return VerificationResult.invalid(
        errors: ['signature invalid'],
      );
    }

    return VerificationResult.ok();
  }

  VerificationResult _verifyProofProperties(dynamic proof) {
    final expires = proof['expires'];
    if (expires != null && getNow().isAfter(DateTime.parse(expires))) {
      return VerificationResult.invalid(errors: ['proof is no longer valid']);
    }

    final proofDomain = proof['domain'];
    final proofChallenge = proof['challenge'];

    if (proofDomain != null) {
      bool isDomainValid = false;
      if (proofDomain is String) {
        isDomainValid = proofDomain.trim().isNotEmpty && domain != null
            ? domain!.contains(proofDomain)
            : true;
      } else if (proofDomain is List) {
        isDomainValid = proofDomain.every((d) =>
            d.trim().isNotEmpty && domain != null ? domain!.contains(d) : true);
      }

      if (!isDomainValid) {
        return VerificationResult.invalid(
            errors: ['invalid or missing proof.domain']);
      }
      if (proofDomain is! String && proofDomain is! List) {
        return VerificationResult.invalid(
            errors: ['invalid proof.domain format']);
      }
      if (proofChallenge == null ||
          proofChallenge is! String ||
          proofChallenge.trim().isEmpty) {
        return VerificationResult.invalid(
            errors: ['invalid or missing proof.challenge']);
      }

      if (challenge != null && proofChallenge != challenge) {
        return VerificationResult.invalid(
            errors: ['invalid or missing proof.challenge']);
      }
    } else if (proofChallenge != null) {
      return VerificationResult.invalid(
          errors: ['proof.challenge must be accompanied by proof.domain']);
    }
    return VerificationResult.ok();
  }

  @override
  Future<VerificationResult> validate(Map<String, dynamic> document) async {
    final copy = Map.of(document);
    final proof = copy.remove('proof');

    if (proof == null || proof is! Map<String, dynamic>) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof'],
      );
    }

    final proofValidationResult = _verifyProofProperties(proof);
    return proofValidationResult;
  }
}

class EcdsaSecp256k1Signature2019Proof extends EmbeddedProof {
  final String jws;

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

Future<Uint8List> _computeVcHash(
  Map<String, dynamic> proof,
  Map<String, dynamic> unsignedCredential,
  Function(Uri url, LoadDocumentOptions? options) documentLoader,
) async {
  final normalizedProof = await JsonLdProcessor.normalize(
    proof,
    options: JsonLdOptions(
      safeMode: true,
      documentLoader: documentLoader,
    ),
  );
  final proofDigest = _sha256.process(
    utf8.encode(normalizedProof),
  );

  final normalizedContent = await JsonLdProcessor.normalize(
    unsignedCredential,
    options: JsonLdOptions(
      safeMode: true,
      documentLoader: documentLoader,
    ),
  );

  final contentDigest = Digest('SHA-256').process(
    utf8.encode(normalizedContent),
  );

  final payloadToSign = Uint8List.fromList(proofDigest + contentDigest);
  return payloadToSign;
}

Future<bool> _verifyJws(
  String jws,
  String issuerDid,
  Uri verificationMethod,
  Uint8List payloadToSign,
) async {
  final jwsParts = jws.split('..');
  if (jwsParts.length != 2) {
    throw SsiException(
      message: 'Invalid jws format',
      code: SsiExceptionType.other.code,
    );
  }

  final encodedHeader = jwsParts[0];
  final encodedSignature = jwsParts[1];

  final signature = base64UrlNoPadDecode(encodedSignature);

  final jwsToSign = Uint8List.fromList(
    utf8.encode(encodedHeader) + utf8.encode('.') + payloadToSign,
  );

//FIXME assuming fully qualified key id (which probably it should be :))
  final verifier = await DidVerifier.create(
    algorithm: SignatureScheme.ecdsa_secp256k1_sha256,
    kid: verificationMethod.toString(),
    issuerDid: issuerDid,
  );
  return verifier.verify(jwsToSign, signature);
}

typedef _LibDocumentLoader = Future<RemoteDocument> Function(
  Uri url,
  LoadDocumentOptions? options,
);

_LibDocumentLoader _cacheLoadDocument(
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

final _documentCache = <Uri, RemoteDocument>{
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
  Uri.parse('https://www.w3.org/ns/credentials/v2'):
      RemoteDocument(document: jsonDecode(r'''
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
        "JsonSchemaCredential": "https://www.w3.org/2018/credentials#JsonSchemaCredential",
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
        "BitstringStatusListCredential": "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",
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
                "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
                "ttl": "https://www.w3.org/ns/credentials/status#ttl"
            }
        },
        "BitstringStatusListEntry": {
            "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
            "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "statusListCredential": {
                    "@id": "https://www.w3.org/ns/credentials/status#statusListCredential",
                    "@type": "@id"
                },
                "statusListIndex": "https://www.w3.org/ns/credentials/status#statusListIndex",
                "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
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
''')),
};
