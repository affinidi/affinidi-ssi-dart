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
import 'proof_purpose.dart';

final _sha256 = Digest('SHA-256');

class EcdsaSecp256k1Signature2019CreateOptions
    extends EmbeddedProofSuiteCreateOptions {
  final DidSigner signer;
  final ProofPurpose proofPurpose;

  /// The date and time when this proof expires.
  final DateTime? expires;

  /// The domains this proof is bound to.
  /// Can be a single string or a list of strings.
  final List<String>? domain;

  /// A challenge to prevent replay attacks.
  final String? challenge;

  EcdsaSecp256k1Signature2019CreateOptions({
    required this.signer,
    this.proofPurpose = ProofPurpose.assertionMethod,
    super.customDocumentLoader,
    this.expires,
    this.domain,
    this.challenge,
  });
}

class EcdsaSecp256k1Signature2019VerifyOptions
    extends EmbeddedProofSuiteVerifyOptions {
  final String issuerDid;
  EcdsaSecp256k1Signature2019VerifyOptions({
    required this.issuerDid,
    super.customDocumentLoader,
  });
}

class EcdsaSecp256k1Signature2019
    implements
        EmbeddedProofSuite<EcdsaSecp256k1Signature2019CreateOptions,
            EcdsaSecp256k1Signature2019VerifyOptions> {
  static const _signatureType = 'EcdsaSecp256k1Signature2019';
  static const _securityContext = 'https://w3id.org/security/v2';

  @override
  Future<EmbeddedProof> createProof(
    Map<String, dynamic> document,
    EcdsaSecp256k1Signature2019CreateOptions options,
  ) async {
    final created = DateTime.now();
    final proof = {
      '@context': _securityContext,
      'type': _signatureType,
      'created': created.toIso8601String(),
      'verificationMethod': options.signer.keyId,
      'proofPurpose': options.proofPurpose.value,
      'expires': options.expires?.toIso8601String(),
      'challenge': options.challenge,
      'domain': options.domain,
    };

    document.remove('proof');

    final cacheLoadDocument = _cacheLoadDocument(options.customDocumentLoader);
    final jws = await _computeVcHash(proof, document, cacheLoadDocument).then(
      (hash) => _computeJws(hash, options.signer),
    );

    proof.remove('@context');
    proof['jws'] = jws;

    return EcdsaSecp256k1Signature2019Proof(
        type: 'EcdsaSecp256k1Signature2019',
        created: created,
        verificationMethod: options.signer.keyId,
        proofPurpose: options.proofPurpose.value,
        jws: jws,
        expires: options.expires,
        challenge: options.challenge,
        domain: options.domain);
  }

  @override
  Future<VerificationResult> verifyProof(
    Map<String, dynamic> document,
    EcdsaSecp256k1Signature2019VerifyOptions options,
  ) async {
    final copy = Map.of(document);
    final proof = copy.remove('proof');

    if (proof == null || proof is! Map<String, dynamic>) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof'],
      );
    }

    final isValidProof = verifyProofProperties(proof);
    if (!isValidProof.isValid) {
      return isValidProof;
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

    final cacheLoadDocument = _cacheLoadDocument(options.customDocumentLoader);
    final isValid = await _computeVcHash(proof, copy, cacheLoadDocument).then(
      (hash) => _verifyJws(
          originalJws as String, options.issuerDid, verificationMethod, hash),
    );

    if (!isValid) {
      return VerificationResult.invalid(
        errors: ['signature invalid'],
      );
    }

    return VerificationResult.ok();
  }

  static VerificationResult verifyProofProperties(dynamic proof) {
    final expires = proof['expires'];
    final now = DateTime.now();
    if (expires != null && now.isAfter(DateTime.parse(expires))) {
      return VerificationResult.invalid(errors: ['proof is no longer valid']);
    }

    final domain = proof['domain'];
    final challenge = proof['challenge'];

    if (domain != null) {
      if (domain is String) {
        if (domain.trim().isEmpty) {
          return VerificationResult.invalid(
              errors: ['invalid or missing proof.domain']);
        }
        if (challenge != null &&
            (challenge is! String || challenge.trim().isEmpty)) {
          return VerificationResult.invalid(
              errors: ['invalid or missing proof.challenge']);
        }
      } else if (domain is List) {
        if (domain.any((d) => d is! String || (d).trim().isEmpty)) {
          return VerificationResult.invalid(
              errors: ['invalid or missing proof.domain']);
        }
        if (challenge != null &&
            (challenge is! String || challenge.trim().isEmpty)) {
          return VerificationResult.invalid(
              errors: ['invalid or missing proof.challenge']);
        }
      } else {
        return VerificationResult.invalid(
            errors: ['invalid proof.domain format']);
      }
      if (challenge == null) {
        return VerificationResult.invalid(
            errors: ['invalid or missing proof.challenge']);
      }
    } else if (challenge != null) {
      return VerificationResult.invalid(
          errors: ['proof.challenge must be accompanied by proof.domain']);
    }
    return VerificationResult.ok();
  }

  static Future<Uint8List> _computeVcHash(
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

  static Future<bool> _verifyJws(
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
};
