import 'dart:convert';
import 'dart:developer' as developer;

import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../factories/vc_suite.dart';
import '../models/parsed_vc.dart';
import '../models/verifiable_credential.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';

abstract class LdOptions {}

typedef ParseFunction<Model extends ParsedVerifiableCredential<String>> = Model
    Function(String input);

/// Class to parse and convert a json representation of a [VerifiableCredential]
abstract class LdBaseSuite<
    Model extends ParsedVerifiableCredential<String>,
    Options extends LdOptions,
    SerializedType> implements VerifiableCredentialSuite<String, Options> {
  final String contextUrl;
  final ParseFunction<Model> parser;

  final String proofKey;
  final String contextKey;
  final String issuerKey;

  LdBaseSuite({
    required this.parser,
    required this.contextUrl,
    this.proofKey = 'proof',
    this.contextKey = '@context',
    this.issuerKey = 'issuer',
  });

  bool _hasExpectedContext(Object data) {
    if (data is! Map || !data.containsKey(contextKey)) return false;

    final context = data[contextKey];
    return (context is List) && context.contains(contextUrl);
  }

  @override
  bool canParse(Object input) {
    if (input is! String) return false;

    // filter out JWT tokens
    if (input.startsWith('ey')) return false;

    // FIXME(cm) decoding twice in canParse and parse
    Map data;
    try {
      data = jsonDecode(input) as Map<String, dynamic>;
    } catch (e) {
      developer.log(
        'LdBaseSuite jsonDecode failed',
        level: 500, // FINE
      );
      return false;
    }

    if (!_hasExpectedContext(data)) return false;

    return data.containsKey(proofKey);
  }

  @override
  Future<String> issue(
    VerifiableCredential vc,
    DidSigner signer, {
    Options? options,
  }) async {
    //TODO(cm): extend option to select proof suite
    var json = vc.toJson() as Map<String, dynamic>;

    // remove proof in case it's already there
    json.remove(proofKey);

    // set the issuer to match the signer
    json[issuerKey] = signer.did;

    final proof = await _proofSuite.createProof(
      vc.toJson() as Map<String, dynamic>,
      EcdsaSecp256k1Signature2019Options(signer: signer),
    );

    json[proofKey] = proof.toJson();

    return jsonEncode(json);
  }

  @override
  ParsedVerifiableCredential<String> parse(Object input) {
    if (input is! String) {
      throw SsiException(
        message: 'Only String is supported',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }
    return parser(input);
  }

  @override
  Future<bool> verifyIntegrity(String input) async {
    //TODO(cm): return verification result
    //TODO(cm): discover proof type
    final proofSuite = EcdsaSecp256k1Signature2019();
    final verificationResult = await proofSuite.verifyProof(
      jsonDecode(input) as Map<String, dynamic>,
    );

    return verificationResult.isValid;
  }

  @override
  Future<bool> verifyExpiry(VerifiableCredential data) async {
    DateTime now = DateTime.now();
    DateTime? validFrom = data.validFrom;
    DateTime? validUntil = data.validUntil;

    if (validFrom != null && now.isBefore(validFrom)) {
      return false;
    }
    if (validUntil != null && now.isAfter(validUntil)) {
      return false;
    }

    return true;
  }
}

final _proofSuite = EcdsaSecp256k1Signature2019();
