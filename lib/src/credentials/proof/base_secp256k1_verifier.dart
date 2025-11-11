import 'dart:convert';
import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:pointycastle/api.dart';

import '../../did/did_resolver.dart';
import '../../did/did_verifier.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../util/base64_util.dart';
import 'embedded_proof_suite.dart';

/// Base class for SECP256K1 signature verifiers.
abstract class BaseSecp256k1Verifier extends EmbeddedProofSuiteVerifyOptions
    implements EmbeddedProofVerifier {
  /// The DID of the issuer.
  final String issuerDid;

  /// Function to get the current time.
  final DateTime Function() getNow;

  /// Optional domain restriction.
  final List<String>? domain;

  /// Optional challenge value.
  final String? challenge;

  /// Optional custom DID resolver for offline/test verification.
  final DidResolver? didResolver;

  /// Creates a new BaseSecp256k1Verifier.
  BaseSecp256k1Verifier({
    required this.issuerDid,
    this.getNow = DateTime.now,
    this.domain,
    this.challenge,
    this.didResolver,
    super.customDocumentLoader,
  });

  /// The expected proof type.
  String get expectedProofType;

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

    proof['@context'] = contextUrl;

    final cacheLoadDocument = _cacheLoadDocument(customDocumentLoader);
    final hash = await computeSignatureHash(proof, copy, cacheLoadDocument);
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

    return VerificationResult.ok();
  }

  VerificationResult _validateExpiry(Map<String, dynamic> proof, DateTime now) {
    final expires = proof['expires'];
    if (expires != null && now.isAfter(expires as DateTime)) {
      return VerificationResult.invalid(errors: ['Not valid proof']);
    }
    return VerificationResult.ok();
  }
}

/// Computes VC hash from proof and document.
Future<Uint8List> computeVcHash(
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
  final proofDigest = Digest('SHA-256').process(
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

/// Verifies a JWS signature.
Future<bool> verifyJws(
  String jws,
  String issuerDid,
  Uri verificationMethod, // expected kid / verification method DID URL
  Uint8List payloadToSign, // canonicalized UTF-8 bytes of the JSON-LD document
  {DidResolver? didResolver}
) async {
  // 1) Parse JWS compact or RFC7797 detached (header..signature)
  String encodedHeader;
  String? encodedPayloadFromJws; // only present in 3-part JWS
  String encodedSignature;

  if (jws.contains('..')) {
    final parts = jws.split('..');
    if (parts.length != 2) {
      throw SsiException(
          message: 'Invalid detached JWS format',
          code: SsiExceptionType.other.code);
    }
    encodedHeader = parts[0];
    encodedSignature = parts[1];
  } else {
    final parts = jws.split('.');
    if (parts.length != 3) {
      throw SsiException(
          message: 'Invalid JWS compact serialization',
          code: SsiExceptionType.other.code);
    }
    encodedHeader = parts[0];
    encodedPayloadFromJws = parts[1];
    encodedSignature = parts[2];
  }

  // 2) Decode header
  final headerBytes = base64UrlNoPadDecode(encodedHeader);
  final headerJson = utf8.decode(headerBytes);
  final header = json.decode(headerJson) as Map<String, dynamic>;

  // 3) Validate alg
  final alg = header['alg'] as String?;
  if (alg == null) {
    throw SsiException(
        message: 'Missing alg in JWS header',
        code: SsiExceptionType.other.code);
  }
  if (alg != 'ES256K' && alg != 'ES256K-R') {
    // ES256K-R (recovery) is sometimes used by some suites; accept if you support it.
    throw SsiException(
        message: 'Unsupported alg: $alg', code: SsiExceptionType.other.code);
  }

  // 4) b64 handling
  final b64Raw = header.containsKey('b64') ? header['b64'] : null;
  final bool b64 = b64Raw == null ? true : (b64Raw == true);
  if (b64Raw == false) {
    final crit = header['crit'];
    if (crit is! List || !crit.contains('b64')) {
      throw SsiException(
          message: 'Invalid header: b64=false must appear in crit',
          code: SsiExceptionType.other.code);
    }
    // If compact serialization included a payload part when b64=false, this should be empty (RFC7797).
    if (encodedPayloadFromJws != null && encodedPayloadFromJws.isNotEmpty) {
      throw SsiException(
          message:
              'Invalid compact serialization: encoded payload must be empty when b64=false',
          code: SsiExceptionType.other.code);
    }
  }

  // 5) kid/verification method check (tighten matching)
  final headerKid = header['kid'] as String?;
  if (headerKid != null) {
    final expectedKid = verificationMethod.toString();
    final expectedFragment =
        expectedKid.contains('#') ? expectedKid.split('#').last : null;
    final headerIsFragment =
        headerKid.startsWith('#') ? headerKid.substring(1) : headerKid;
    final bool kidMatches = headerKid == expectedKid ||
        (expectedFragment != null && (headerIsFragment == expectedFragment)) ||
        // also accept `kid=` fragment style in some VC usages: e.g. did:...#kid=BASE64
        (expectedKid.contains('#') &&
            expectedKid.split('#').last.startsWith('kid=') &&
            headerKid == expectedKid.split('#').last);
    if (!kidMatches) {
      throw SsiException(
          message:
              'kid mismatch between JWS header and expected verificationMethod',
          code: SsiExceptionType.other.code);
    }
  }

  // 6) Build signing input
  Uint8List signingInput;
  if (b64) {
    final encodedPayload = base64UrlNoPadEncode(payloadToSign);
    if (encodedPayloadFromJws != null &&
        encodedPayloadFromJws != encodedPayload) {
      throw SsiException(
          message: 'Payload mismatch between provided payload and JWS payload',
          code: SsiExceptionType.other.code);
    }
    final headerAndDot = utf8.encode(encodedHeader) + utf8.encode('.');
    final payloadBytes = utf8.encode(encodedPayload);
    signingInput = Uint8List.fromList(headerAndDot + payloadBytes);
  } else {
    // b64 == false -> raw payload bytes are used directly
    final headerAndDot = utf8.encode(encodedHeader) + utf8.encode('.');
    signingInput = Uint8List.fromList(headerAndDot + payloadToSign);
  }

  // 7) Decode signature bytes
  Uint8List signature = base64UrlNoPadDecode(encodedSignature);

  // 8) Create verifier
  final verifier = await DidVerifier.create(
    algorithm: SignatureScheme.ecdsa_secp256k1_sha256,
    kid: verificationMethod.toString(),
    issuerDid: issuerDid,
    didResolver: didResolver,
  );

  // 9) Verify: try as-is, then if fails and signature looks like DER, convert to r||s and retry
  bool ok = false;
  try {
    ok = verifier.verify(signingInput, signature);
    if (ok) {
      return true;
    }
  } catch (e) {
    // ignore; we'll try conversion path below
  }

  // If signature length is DER (starts with 0x30) or variable-length and not 64, try DER->P1363
  if (signature.length != 64 && signature.isNotEmpty && signature[0] == 0x30) {
    try {
      final p1363 = _derToP1363(signature, 32); // 32-byte coords for secp256k1
      ok = verifier.verify(signingInput, p1363);
      return ok;
    } catch (e) {
      // fall through
    }
  }

  // If signature is 64 bytes, verification was already attempted above; if it fails, return false.
  if (signature.length == 64) {
    // already tried as-is above, so failing here means verification failed
    return false;
  }

  // If we reach here, verification failed
  return false;
}

// Helper: convert ASN.1 DER encoded ECDSA signature -> P1363 r||s
Uint8List _derToP1363(Uint8List der, int coordinateLength) {
  // Simple minimal ASN.1 parser enough for ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }
  if (der.isEmpty || der[0] != 0x30) {
    throw ArgumentError('Not a DER SEQUENCE');
  }
  int idx = 1;
  if (idx >= der.length) {
    throw ArgumentError('Invalid DER');
  }
  int seqLen = der[idx++];
  if (seqLen & 0x80 != 0) {
    final numBytes = seqLen & 0x7F;
    if (numBytes == 0 || idx + numBytes > der.length) {
      throw ArgumentError('Invalid DER length');
    }
    seqLen = 0;
    for (int i = 0; i < numBytes; i++) {
      seqLen = (seqLen << 8) | der[idx++];
    }
  }
  // parse INTEGER r
  if (idx >= der.length || der[idx++] != 0x02) {
    throw ArgumentError('Expected INTEGER for r');
  }
  int rLen = der[idx++];
  if (rLen & 0x80 != 0) {
    final numBytes = rLen & 0x7F;
    if (numBytes == 0 || idx + numBytes > der.length) {
      throw ArgumentError('Invalid r length');
    }
    rLen = 0;
    for (int i = 0; i < numBytes; i++) {
      rLen = (rLen << 8) | der[idx++];
    }
  }
  if (idx + rLen > der.length) {
    throw ArgumentError('Truncated r');
  }
  final rBytes = der.sublist(idx, idx + rLen);
  idx += rLen;

  // parse INTEGER s
  if (idx >= der.length || der[idx++] != 0x02) {
    throw ArgumentError('Expected INTEGER for s');
  }
  int sLen = der[idx++];
  if (sLen & 0x80 != 0) {
    final numBytes = sLen & 0x7F;
    if (numBytes == 0 || idx + numBytes > der.length) {
      throw ArgumentError('Invalid s length');
    }
    sLen = 0;
    for (int i = 0; i < numBytes; i++) {
      sLen = (sLen << 8) | der[idx++];
    }
  }
  if (idx + sLen > der.length) {
    throw ArgumentError('Truncated s');
  }
  final sBytes = der.sublist(idx, idx + sLen);
  // rBytes and sBytes are minimal signed big-endian integers: they may have a leading 0x00 to indicate positive
  Uint8List r = _trimLeadingZero(rBytes);
  Uint8List s = _trimLeadingZero(sBytes);

  // pad to coordinateLength
  if (r.length > coordinateLength || s.length > coordinateLength) {
    throw ArgumentError('Coordinate length too big for curve');
  }
  final rPadded = _leftPad(r, coordinateLength);
  final sPadded = _leftPad(s, coordinateLength);

  return Uint8List.fromList(rPadded + sPadded);
}

Uint8List _trimLeadingZero(Uint8List inBytes) {
  int i = 0;
  while (i < inBytes.length - 1 && inBytes[i] == 0) {
    i++;
  }
  return inBytes.sublist(i);
}

Uint8List _leftPad(Uint8List src, int length) {
  if (src.length == length) {
    return src;
  }
  final out = Uint8List(length);
  final offset = length - src.length;
  out.setRange(offset, length, src);
  return out;
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
