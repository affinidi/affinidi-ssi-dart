import 'dart:convert';

import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/doc_with_embedded_proof.dart';
import '../models/verifiable_credential.dart';
import '../parsers/ld_parser.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';
import '../proof/proof_purpose.dart';

/// Options for LD based data model operations.
///
/// Contains configuration parameters for LD based data model operations
/// in the context of W3C Verifiable Credentials Data Model.
abstract class LdOptions {
  /// The date and time when embedded proof expires.
  final DateTime? expires;

  /// The domains this proof is bound to.
  /// Can be a single string or a list of strings.
  final List<String>? domain;

  /// A challenge to prevent replay attacks.
  final String? challenge;

  /// The purpose of embedded proof.
  final ProofPurpose? proofPurpose;

  /// Creates an options object for LdOptions.
  ///
  /// [expires] - Specify expiry of proof.
  /// [domain] - Specify one or more security domains in which the proof is meant to be used.
  /// [challenge] - Specify challenge for domain in proof.
  /// [proofPurpose] - Specify proofPurpose
  LdOptions({this.expires, this.domain, this.challenge, this.proofPurpose});
}

/// Class to parse and convert a json representation of a [VerifiableCredential]
abstract class LdBaseSuite<VC extends DocWithEmbeddedProof, Model extends VC,
    Options extends LdOptions> with LdParser {
  final String contextUrl;

  final String proofKey;
  final String contextKey;
  final String issuerKey;

  LdBaseSuite({
    required this.contextUrl,
    this.proofKey = 'proof',
    this.contextKey = '@context',
    this.issuerKey = 'issuer',
  });

  @override
  bool hasValidPayload(Map<String, dynamic> data) {
    if (!data.containsKey(contextKey)) return false;
    if (!data.containsKey(proofKey)) return false;

    final context = data[contextKey];
    return (context is List) && context.contains(contextUrl);
  }

  bool canParse(Object input) {
    if (input is! String) return false;

    return canDecode(input);
  }

  Model fromParsed(String input, Map<String, dynamic> payload);

  Future<Model> issue(
    VC data,
    DidSigner signer, {
    Options? options,
  }) async {
    //TODO(FTL-20735): extend option to select proof suite
    var json = data.toJson();
    // remove proof in case it's already there
    json.remove(proofKey);

    // set the issuer to match the signer
    json[issuerKey] = signer.did;

    final proof = await _proofSuite.createProof(
      json,
      EcdsaSecp256k1Signature2019CreateOptions(
          signer: signer,
          proofPurpose: options?.proofPurpose,
          expires: options?.expires,
          challenge: options?.challenge,
          domain: options?.domain),
    );

    json[proofKey] = proof.toJson();

    return fromParsed(jsonEncode(json), json);
  }

  Model parse(Object input) {
    if (input is! String) {
      throw SsiException(
        message: 'Only String is supported',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    return fromParsed(input, decode(input));
  }

  Future<bool> verifyIntegrity(Model input) async {
    //TODO(FTL-20735): discover proof type
    final proofSuite = EcdsaSecp256k1Signature2019();
    final document = input.toJson();
    final issuerDid = document[issuerKey] as String;
    final verificationResult = await proofSuite.verifyProof(
      document,
      EcdsaSecp256k1Signature2019VerifyOptions(issuerDid: issuerDid),
    );

    return verificationResult.isValid;
  }

  Map<String, dynamic> present(Model input) {
    return input.toJson();
  }
}

final _proofSuite = EcdsaSecp256k1Signature2019();
