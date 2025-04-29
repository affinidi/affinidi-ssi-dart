import 'dart:convert';

import 'package:ssi/src/credentials/models/field_types/issuer.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/doc_with_embedded_proof.dart';
import '../models/verifiable_credential.dart';
import '../parsers/ld_parser.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';
import '../proof/embedded_proof_suite.dart';

/// Class to parse and convert a json representation of a [VerifiableCredential]
abstract class LdBaseSuite<VC extends DocWithEmbeddedProof, Model extends VC>
    with LdParser {
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

  Model parse(Object input) {
    if (input is! String) {
      throw SsiException(
        message: 'Only String is supported',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    return fromParsed(input, decode(input));
  }

  Future<bool> verifyIntegrity(Model input,
      {DateTime Function() getNow = DateTime.now}) async {
    //TODO(FTL-20735): discover proof type
    final document = input.toJson();
    final issuerDid = Issuer.uri(document[issuerKey]);
    final proofSuite =
        Secp256k1Signature2019Verifier(issuerDid: issuerDid.id.toString());
    final verificationResult =
        await proofSuite.verify(document, getNow: getNow);

    return verificationResult.isValid;
  }

  Map<String, dynamic> present(Model input) {
    return input.toJson();
  }
}
