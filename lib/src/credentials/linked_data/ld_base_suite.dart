import 'dart:convert';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/doc_with_embedded_proof.dart';
import '../models/field_types/issuer.dart';
import '../models/verifiable_credential.dart';
import '../parsers/ld_parser.dart';
import '../proof/data_integrity_ecdsa_suite.dart';
import '../proof/data_integrity_eddsa_suite.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';
import '../proof/embedded_proof_suite.dart'
    show DocumentLoader, EmbeddedProofGenerator, EmbeddedProofVerifier;
import '../proof/jcs_utils.dart';

/// A no-operation document loader that always returns null.
Future<Map<String, dynamic>?> _noOpLoader(Uri url) async {
  return Future.value(null);
}

/// Class to parse and convert a json representation of a [VerifiableCredential]
abstract class LdBaseSuite<VC extends DocWithEmbeddedProof, Model extends VC>
    with LdParser {
  /// The required context url
  final String contextUrl;

  /// The JSON key used for the proof object (default: 'proof').
  final String proofKey;

  /// The JSON key used for the context object (default: '@context').
  final String contextKey;

  /// The JSON key used for the issuer field (default: 'issuer').
  final String issuerKey;

  /// Custom document loader for loading external resources during verification.
  ///
  /// This loader is used to load external resources like JSON-LD contexts and
  /// DID documents during verification.
  ///
  /// If not provided, a default no-op loader is used, which always returns null.
  final DocumentLoader? customDocumentLoader;

  /// Constructs a new [LdBaseSuite] with the required context URL.
  ///
  /// Optional [proofKey], [contextKey], [issuerKey], and [customDocumentLoader] parameters
  LdBaseSuite({
    required this.contextUrl,
    this.proofKey = 'proof',
    this.contextKey = '@context',
    this.issuerKey = 'issuer',
    this.customDocumentLoader,
  });

  @override
  bool hasValidPayload(Map<String, dynamic> data) {
    if (!data.containsKey(contextKey)) return false;
    if (!data.containsKey(proofKey)) return false;

    final context = data[contextKey];
    return (context is List) && context.contains(contextUrl) ||
        (context is String) && context == contextUrl;
  }

  /// Checks if the given [input] can be parsed.
  ///
  /// Returns `true` if [input] is a String and can be decoded into a JSON object.
  bool canParse(Object input) {
    if (input is! String) return false;

    return canDecode(input);
  }

  /// Creates a [Model] instance from the parsed JSON [payload] and original [input] string.
  Model fromParsed(String input, Map<String, dynamic> payload);

  /// Attempts to parse the [input] and returns the result if successful, null otherwise.
  Model? tryParse(Object input) {
    if (!canParse(input)) return null;

    try {
      return parse(input);
    } catch (e) {
      return null;
    }
  }

  /// Issues a signed [Model] by applying an embedded proof.
  ///
  /// Throws a [SsiException] if the issuer in the proof does not match the credential's
  Future<Model> issue({
    required VC unsignedData,
    required EmbeddedProofGenerator proofGenerator,
  }) async {
    var json = unsignedData.toJson();
    // remove proof in case it's already there
    json.remove(proofKey);

    final proof = await proofGenerator.generate(json);

    final issuer = Issuer.fromJson(json[issuerKey]);
    if (proof.verificationMethod?.split('#').first != issuer.id.toString()) {
      throw SsiException(
        message: 'Issuer mismatch',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    json[proofKey] = proof.toJson();

    return fromParsed(jsonEncode(json), json);
  }

  /// Parses the [input] string into a [Model].
  ///
  /// Throws a [SsiException] if [input] is not a valid String.
  Model parse(Object input) {
    if (input is! String) {
      throw SsiException(
        message: 'Only String is supported',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    return fromParsed(input, decode(input));
  }

  /// Verifies the cryptographic integrity of the [input] credential.
  ///
  /// Optionally accepts [getNow] to provide a custom "now" time for expiry and validity
  Future<bool> verifyIntegrity(Model input,
      {DateTime Function() getNow = DateTime.now}) async {
    final document = input.toJson();
    final proofSuite = _getDocumentProofVerifier(document);

    if (proofSuite == null) {
      return false;
    }

    final verificationResult =
        await proofSuite.verify(document, getNow: getNow);
    return verificationResult.isValid;
  }

  EmbeddedProofVerifier? _getDocumentProofVerifier(
      Map<String, dynamic> document) {
    final proof = document[proofKey];
    if (proof == null || proof is! Map<String, dynamic>) {
      return null;
    }

    final proofType = proof['type'] as String?;
    if (proofType == null) {
      return null;
    }

    final issuerDid = Issuer.uri(document[issuerKey]).id.toString();

    final vm = proof['verificationMethod'] as String?;
    if (vm == null) {
      return null;
    }
    final vmDid = vm.split('#').first;
    if (vmDid != issuerDid) {
      throw SsiException(
        message:
            'Issuer mismatch: issuer DID and proof.verificationMethod DID differ',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    final loader = customDocumentLoader ?? _noOpLoader;
    switch (proofType) {
      case 'DataIntegrityProof':
        final cryptosuite = proof['cryptosuite'] as String?;
        switch (cryptosuite) {
          case 'ecdsa-rdfc-2019':
            return DataIntegrityEcdsaRdfcVerifier(
              issuerDid: issuerDid,
              customDocumentLoader: loader,
            );
          case JcsUtils.ecdsaJcs2019:
            return DataIntegrityEcdsaJcsVerifier(
              verifierDid: issuerDid,
              customDocumentLoader: loader,
            );
          case 'eddsa-rdfc-2022':
            return DataIntegrityEddsaRdfcVerifier(
              issuerDid: issuerDid,
              customDocumentLoader: loader,
            );
          case JcsUtils.eddsaJcs2022:
            return DataIntegrityEddsaJcsVerifier(
              verifierDid: issuerDid,
              customDocumentLoader: loader,
            );
          default:
            return null;
        }
      case 'EcdsaSecp256k1Signature2019':
        return Secp256k1Signature2019Verifier(
          issuerDid: issuerDid,
          customDocumentLoader: loader,
        );
      default:
        return null;
    }
  }

  /// Presents the [input] credential as a JSON object.
  Map<String, dynamic> present(Model input) {
    return input.toJson();
  }
}
