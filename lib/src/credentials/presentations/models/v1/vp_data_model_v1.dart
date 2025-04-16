import 'dart:convert';

import '../../../../../ssi.dart';
import '../../../../util/json_util.dart';
import '../../../models/parsed_vc.dart';
import '../../../suites/vc_suites.dart';
import 'vp_data_model_v1_view.dart';

/// Represents a Verifiable Presentation (VP) according to the W3C VC Data Model v1.1.
///
/// A Verifiable Presentation is a container for one or more Verifiable Credentials (VCs),
/// optionally including a `proof` issued by the `holder`.
///
/// This class supports JSON serialization and deserialization for interoperability.
///
/// Example:
/// ```dart
/// final vp = VpDataModelV1(
///   context: ['https://www.w3.org/2018/credentials/v1'],
///   type: ['VerifiablePresentation'],
///   holder: 'did:example:holder',
///   verifiableCredential: [vc],
/// );
/// ```
class MutableVpDataModelV1 implements VpDataModelV1 {
  static const String contextUrl = 'https://www.w3.org/2018/credentials/v1';

  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  @override
  List<String> context;

  /// The optional identifier for this presentation.
  @override
  String? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  @override
  List<String> type;

  /// The identifier of the holder presenting the credentials.
  ///
  /// Typically a DID.
  @override
  String? holder;

  /// The list of verifiable credentials embedded in this presentation.
  @override
  List<ParsedVerifiableCredential> verifiableCredential;

  /// The cryptographic proof created by the holder.
  @override
  Map<String, dynamic> proof;

  /// Creates a [VpDataModelV1] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [type] is an array that must include 'VerifiablePresentation'.
  /// The [holder] is an identifier for the presenter (optional).
  /// The [verifiableCredential] is a list of embedded credentials (optional).
  /// The [proof] is a cryptographic proof (optional).
  MutableVpDataModelV1({
    required this.context,
    this.id,
    required this.type,
    this.holder,
    List<ParsedVerifiableCredential>? verifiableCredential,
    Map<String, dynamic>? proof,
  })  : verifiableCredential = verifiableCredential ?? [],
        proof = proof ?? {};

  /// Converts this presentation to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    if (id != null) json[_P.id.key] = id;
    json[_P.type.key] = type;
    if (holder != null) json[_P.holder.key] = holder;

    if (verifiableCredential.isNotEmpty) {
      json[_P.verifiableCredential.key] =
          verifiableCredential.map(presentVC).toList();
    }

    if (proof.isNotEmpty) {
      json[_P.proof.key] = proof;
    }

    return json;
  }

  /// Creates a [VpDataModelV1] from JSON input.
  ///
  /// The [input] can be a JSON string or a [Map<String, dynamic>].
  /// Parses both mandatory and optional fields.
  MutableVpDataModelV1.fromJson(dynamic input)
      : context = [],
        type = [],
        verifiableCredential = [],
        proof = {} {
    final json = jsonToMap(input);

    context = getStringList(json, _P.context.key, mandatory: true);
    id = getString(json, _P.id.key);
    type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    );
    holder = getString(json, _P.holder.key);

    // Handles both single VC or a list of VCs
    final credentials = json[_P.verifiableCredential.key];
    if (credentials != null) {
      if (credentials is List) {
        verifiableCredential = credentials.map(parseVC).toList();
      } else if (credentials is Map) {
        verifiableCredential = [parseVC(credentials)];
      }
    }

    // Parse proof object if present
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

typedef _P = VpDataModelV1Key;

enum VpDataModelV1Key {
  context(key: '@context'),
  id,
  type,
  holder,
  verifiableCredential,
  proof;

  final String? _key;

  String get key => _key ?? name;

  const VpDataModelV1Key({String? key}) : _key = key;
}
