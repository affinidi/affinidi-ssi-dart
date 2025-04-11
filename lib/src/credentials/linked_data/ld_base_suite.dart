import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/doc_with_embedded_proof.dart';
import '../models/verifiable_credential.dart';
import '../parsers/ld_parser.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';

abstract class LdOptions {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
abstract class LdBaseSuite<VDM extends DocWithEmbeddedProof, Model extends VDM,
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

  Model fromJson(Map<String, dynamic> payload);
  Model fromParsed(String input, Map<String, dynamic> payload);

  Future<Model> issue(
    VDM vc,
    DidSigner signer, {
    Options? options,
  }) async {
    //TODO(cm): extend option to select proof suite
    var json = vc.toJson();

    // remove proof in case it's already there
    json.remove(proofKey);

    // set the issuer to match the signer
    json[issuerKey] = signer.did;

    final proof = await _proofSuite.createProof(
      vc.toJson(),
      EcdsaSecp256k1Signature2019Options(signer: signer),
    );

    json[proofKey] = proof.toJson();

    return fromJson(json);
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
    //TODO(cm): return verification result
    //TODO(cm): discover proof type
    final proofSuite = EcdsaSecp256k1Signature2019();
    final verificationResult = await proofSuite.verifyProof(
      input.toJson(),
    );

    return verificationResult.isValid;
  }
}

final _proofSuite = EcdsaSecp256k1Signature2019();
