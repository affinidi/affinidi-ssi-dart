// import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/presentations/models/verifiable_presentation.dart';
import '../../../models/verifiable_credential.dart';
import '../../../../util/json_util.dart';

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
class VpDataModelV2 implements VerifiablePresentation {
  static const String contextUrl = "https://www.w3.org/ns/credentials/v2";

  /// JSON-LD context array. Must include `https://www.w3.org/ns/credentials/v2`
  List<String> context;

  /// Optional identifier for the presentation
  String? id;

  /// Type array. Must include `'VerifiablePresentation'`
  List<String> type;

  /// Optional identifier of the entity presenting the credentials (usually a DID)
  @override
  String? holder;

  /// Optional terms of use describing conditions for credential usage
  List<Map<String, dynamic>> termsOfUse;

  /// One or more Verifiable Credentials included in the presentation
  @override
  List<VerifiableCredential> verifiableCredential;

  /// Cryptographic proof object (e.g. DataIntegrityProof, JWT, etc.)
  Map<String, dynamic> proof;

  /// Creates a [VpDataModelV2] instance.
  VpDataModelV2({
    required this.context,
    this.id,
    required this.type,
    this.holder,
    List<Map<String, dynamic>>? termsOfUse,
    List<VerifiableCredential>? verifiableCredential,
    Map<String, dynamic>? proof,
  })  : termsOfUse = termsOfUse ?? [],
        verifiableCredential = verifiableCredential ?? [],
        proof = proof ?? {};

  /// Converts the VP to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    final Map<String, dynamic> json = {};

    json['@context'] = context;
    if (id != null) json['id'] = id;
    json['type'] = type;
    if (holder != null) json['holder'] = holder;
    if (termsOfUse.isNotEmpty) json['termsOfUse'] = termsOfUse;

    if (verifiableCredential.isNotEmpty) {
      json['verifiableCredential'] =
          verifiableCredential.map((vc) => vc.toJson()).toList();
    }

    if (proof.isNotEmpty) {
      json['proof'] = proof;
    }

    return json;
  }

  /// Creates a [VpDataModelV2] instance from JSON or JSON-like input.
  ///
  /// This method supports context normalization, handles optional fields,
  /// and accepts both single and array formats for credentials.
  VpDataModelV2.fromJson(dynamic input)
      : context = [],
        type = [],
        termsOfUse = [],
        verifiableCredential = [],
        proof = {} {
    final json = jsonToMap(input);

    context = getStringList(json, '@context', mandatory: true);
    id = getString(json, 'id');
    type = getStringList(json, 'type', allowSingleValue: true, mandatory: true);
    holder = getString(json, 'holder');

    final tou = json['termsOfUse'];
    if (tou != null) {
      if (tou is List) {
        termsOfUse = tou.map((e) => Map<String, dynamic>.from(e)).toList();
      } else if (tou is Map) {
        termsOfUse = [Map<String, dynamic>.from(tou)];
      }
    }

    final credentials = json['verifiableCredential'];
    if (credentials != null) {
      if (credentials is List) {
        //TODO: implement VcDataModelV2.fromJson
        // verifiableCredential = credentials
        //     .map((e) => VcDataModelV2.fromJson(jsonToMap(e)))
        //     .toList();
      } else if (credentials is Map) {
        //TODO: implement VcDataModelV2.fromJson
        // verifiableCredential = [VcDataModelV2.fromJson(jsonToMap(credentials))];
      }
    }

    if (json['proof'] != null && json['proof'] is Map) {
      proof = Map.of(json['proof']);
    }
  }
}
