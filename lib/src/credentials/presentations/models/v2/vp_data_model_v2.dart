// import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'dart:convert';

import 'package:ssi/src/credentials/models/vc_models.dart';

import '../../../../util/json_util.dart';
import '../../../models/holder.dart';
import '../../../models/parsed_vc.dart';
import '../../../proof/embedded_proof.dart';
import '../../../suites/universal_parser.dart';
import '../../../suites/vc_suites.dart';
import 'vp_data_model_v2_view.dart';

/// Represents a Verifiable Presentation (VP) according to the W3C VC Data Model v2.0.
///
/// A Verifiable Presentation in v2.0 may include credentials, cryptographic proof,
/// and optional terms of use. It is expressed using JSON-LD with support for richer
/// semantics and vocabulary extensions.
///
/// Example:
/// ```dart
/// final vp = VpDataModelV2(
///   context: ['https://www.w3.org/ns/credentials/v2'],
///   type: ['VerifiablePresentation'],
///   holder: 'did:example:holder',
///   verifiableCredential: [vc],
/// );
/// ```
class MutableVpDataModelV2 implements VpDataModelV2 {
  /// The default JSON-LD context URL for VP v2
  static const String contextUrl = 'https://www.w3.org/ns/credentials/v2';

  /// The JSON-LD context for this presentation.
  ///
  /// Must include 'https://www.w3.org/ns/credentials/v2'.
  @override
  List<String> context;

  /// The unique identifier for this presentation.
  @override
  String? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  @override
  List<String> type;

  /// The identifier of the entity presenting the credentials.
  ///
  /// Usually a DID.
  @override
  Holder? holder;

  /// The terms of use describing conditions for credential usage.
  @override
  List<TermOfUse> termsOfUse;

  /// The verifiable credentials included in this presentation.
  @override
  List<ParsedVerifiableCredential> verifiableCredential;

  /// The cryptographic proof securing this presentation.
  ///
  /// Can be a DataIntegrityProof, JWT, or other proof format.
  @override
  List<EmbeddedProof> proof;

  /// Creates a [VpDataModelV2] instance.
  ///
  /// The [context] must include the v2 credentials context.
  /// The [type] must include 'VerifiablePresentation'.
  /// The [holder] identifies who is presenting the credentials.
  /// The [termsOfUse] specifies any usage conditions.
  /// The [verifiableCredential] contains the credentials being presented.
  /// The [proof] provides cryptographic verification.
  MutableVpDataModelV2({
    required this.context,
    this.id,
    required this.type,
    this.holder,
    List<TermOfUse>? termsOfUse,
    List<ParsedVerifiableCredential>? verifiableCredential,
    List<EmbeddedProof>? proof,
  })  : termsOfUse = termsOfUse ?? [],
        verifiableCredential = verifiableCredential ?? [],
        proof = proof ?? [EmbeddedProof(type: 'Ed25519Signature2018')];

  /// Converts this presentation to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    if (id != null) json[_P.id.key] = id;
    json[_P.type.key] = type;
    if (holder != null) {
      json[_P.holder.key] = holder!.toJson();
    }

    if (termsOfUse.isNotEmpty) {
      json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    }

    if (verifiableCredential.isNotEmpty) {
      json[_P.verifiableCredential.key] =
          verifiableCredential.map(presentVC).toList();
    }

    json[_P.proof.key] = encodeListToSingleOrArray(proof);

    return json;
  }

  /// Creates a [VpDataModelV2] from JSON input.
  ///
  /// Supports context normalization, handles optional fields, and accepts
  /// both single and array formats for credentials.
  MutableVpDataModelV2.fromJson(dynamic input)
      : context = [],
        type = [],
        termsOfUse = [],
        verifiableCredential = [],
        proof = [] {
    final json = jsonToMap(input);

    context = getStringList(json, _P.context.key, mandatory: true);
    id = getString(json, _P.id.key);
    type = getStringList(json, _P.type.key,
        allowSingleValue: true, mandatory: true);

    if (json.containsKey(_P.holder.key)) {
      holder = Holder.fromJson(json[_P.holder.key]);
    }

    if (json.containsKey(_P.termsOfUse.key)) {
      termsOfUse = parseListOrSingleItem<TermOfUse>(
        json[_P.termsOfUse.key],
        (item) => TermOfUse.fromJson(jsonToMap(item)),
      );
    }

    final credentials = json[_P.verifiableCredential.key];
    if (credentials != null) {
      if (credentials is List) {
        verifiableCredential = credentials.map(parseVC).toList();
      } else if (credentials is Map) {
        verifiableCredential = [parseVC(credentials)];
      }
    }

    if (json.containsKey(_P.proof.key)) {
      proof = parseListOrSingleItem<EmbeddedProof>(
        json[_P.proof.key],
        (item) => EmbeddedProof.fromJson(jsonToMap(item)),
      );
    }
  }
}

/// Parses a [ParsedVerifiableCredential] from JSON or string input.
///
/// Accepts either a raw credential object or its serialized string form.
/// Delegates to [UniversalParser].
ParsedVerifiableCredential parseVC(dynamic e) {
  String encoded;
  if (e is! String) {
    encoded = jsonEncode(e);
  } else {
    encoded = e;
  }

  return UniversalParser.parse(encoded);
}

/// Converts a [ParsedVerifiableCredential] into its presentable form
/// using the appropriate VC suite.
dynamic presentVC(ParsedVerifiableCredential credential) {
  final suite = VcSuites.getVcSuite(credential);
  final present = suite.present(credential);

  if (present is! String || present is! Map<String, dynamic>) {
    return credential.toJson();
  }

  return present;
}

typedef _P = VpDataModelV2Key;

enum VpDataModelV2Key {
  context(key: '@context'),
  id,
  type,
  holder,
  verifiableCredential,
  proof,
  termsOfUse;

  final String? _key;

  String get key => _key ?? name;

  const VpDataModelV2Key({String? key}) : _key = key;
}
