import 'dart:convert';
import 'dart:developer' as developer;

import 'package:ssi/src/credentials/factories/vc_suite.dart';
import 'package:ssi/src/credentials/linked_data/ld_vc_data_model_v1.dart';
import 'package:ssi/src/did/did_signer.dart';

import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import '../proof/ecdsa_secp256k1_signature2019_suite.dart';

class LdVcDm1Options {}

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class LdVcDm1Suite
    implements VerifiableCredentialSuite<String, LdVcDm1Options> {
  static const _v1ContextUrl = 'https://www.w3.org/2018/credentials/v1';

  bool _hasV1Context(Object data) {
    if (data is! Map) return false;

    final context = data[VcDataModelV1Key.context.key];
    return (context is List) && context.contains(_v1ContextUrl);
  }

  @override
  bool canParse(Object input) {
    if (input is! String) return false;

    // filter out JWT tokens
    if (input.startsWith('ey')) return false;

    // FIXME(cm) decoding twice in canParse and parse
    Map data;
    try {
      data = jsonDecode(input);
    } catch (e) {
      developer.log(
        "VcDataModelV1WithProofParser jsonDecode failed",
        level: 500, // FINE
      );
      return false;
    }

    if (!_hasV1Context(data)) return false;

    return data.containsKey(VcDataModelV1Key.proof.key);
  }

  @override
  Future<String> issue(
    VerifiableCredential vc,
    DidSigner signer, {
    LdVcDm1Options? options,
  }) async {
    //TODO(cm): extend option to select proof suite
    final json = vc.toJson();

    // remove proof in case it's already there
    json.remove(VcDataModelV1Key.proof.key);

    // set the issuer to match the signer
    json[VcDataModelV1Key.issuer.key] = signer.did;

    final proof = await _proofSuite.createProof(
      vc.toJson(),
      EcdsaSecp256k1Signature2019Options(signer: signer),
    );

    json[VcDataModelV1Key.proof.key] = proof.toJson();

    return jsonEncode(json);
  }

  @override
  ParsedVerifiableCredential<String> parse(Object input) {
    return LdVcDataModelV1.parse(input as String);
  }

  @override
  Future<bool> verifyIntegrity(String input) async {
    //TODO(cm): return verification result
    //TODO(cm): discover proof type
    final proofSuite = EcdsaSecp256k1Signature2019();
    final verificationResult = await proofSuite.verifyProof(
      jsonDecode(input),
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
