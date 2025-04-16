// import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'dart:convert';

import '../../../../../ssi.dart';
import '../../../../util/json_util.dart';
import '../../../models/parsed_vc.dart';
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
  String? holder;

  /// The terms of use describing conditions for credential usage.
  @override
  List<Map<String, dynamic>> termsOfUse;

  /// The verifiable credentials included in this presentation.
  @override
  List<ParsedVerifiableCredential> verifiableCredential;

  /// The cryptographic proof securing this presentation.
  ///
  /// Can be a DataIntegrityProof, JWT, or other proof format.
  @override
  Map<String, dynamic> proof;

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
    List<Map<String, dynamic>>? termsOfUse,
    List<ParsedVerifiableCredential>? verifiableCredential,
    Map<String, dynamic>? proof,
  })  : termsOfUse = termsOfUse ?? [],
        verifiableCredential = verifiableCredential ?? [],
        proof = proof ?? {};

  /// Converts this presentation to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json['@context'] = context;
    if (id != null) json[_P.id.key] = id;
    json[_P.type.key] = type;
    if (holder != null) json[_P.holder.key] = holder;
    if (termsOfUse.isNotEmpty) json[_P.termsOfUse.key] = termsOfUse;

    if (verifiableCredential.isNotEmpty) {
      json[_P.verifiableCredential.key] =
          verifiableCredential.map(presentVC).toList();
    }

    if (proof.isNotEmpty) {
      json[_P.proof.key] = proof;
    }

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
        proof = {} {
    final json = jsonToMap(input);

    context = getStringList(json, _P.context.key, mandatory: true);
    id = getString(json, _P.id.key);
    type = getStringList(json, _P.type.key,
        allowSingleValue: true, mandatory: true);
    holder = getString(json, _P.holder.key);

    final tou = json[_P.termsOfUse.key];
    if (tou != null) {
      if (tou is List) {
        termsOfUse = tou
            .map((e) => Map<String, dynamic>.from(e as Map<String, dynamic>))
            .toList();
      } else if (tou is Map) {
        termsOfUse = [Map<String, dynamic>.from(tou)];
      }
    }

    final credentials = json[_P.verifiableCredential.key];
    if (credentials != null) {
      if (credentials is List) {
        verifiableCredential = credentials.map(parseVC).toList();
      } else if (credentials is Map) {
        verifiableCredential = [parseVC(credentials)];
      }
    }

    if (json[_P.proof.key] != null && json[_P.proof.key] is Map) {
      proof = Map.of(json[_P.proof.key] as Map<String, dynamic>);
    }
  }
}

ParsedVerifiableCredential parseVC(dynamic e) {
  String encoded;
  if (e is! String) {
    encoded = jsonEncode(e);
  } else {
    encoded = e;
  }

  return UniversalParser.parse(encoded);
}

dynamic presentVC(ParsedVerifiableCredential credential) {
  final suite = VcSuites.getVcSuite(credential);
  return suite.present(credential);
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
