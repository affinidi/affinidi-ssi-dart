import '../../../../util/json_util.dart';
import '../../../models/v1/vc_data_model_v1.dart';
import '../../../models/verifiable_credential.dart';
import '../verifiable_presentation.dart';

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
class VpDataModelV1 implements VerifiablePresentation {
  static const String contextUrl = 'https://www.w3.org/2018/credentials/v1';

  /// JSON-LD context, typically includes: `https://www.w3.org/2018/credentials/v1`
  @override
  List<String> context;

  /// Optional identifier for the presentation
  @override
  String? id;

  /// Type array, mandatory field
  @override
  List<String> type;

  /// Optional identifier of the holder (typically a DID)
  @override
  String? holder;

  /// One or more embedded Verifiable Credentials
  @override
  List<VerifiableCredential> verifiableCredential;

  /// Cryptographic proof created by the holder
  @override
  Map<String, dynamic> proof;

  /// Creates a [VpDataModelV1] instance.
  ///
  /// [context] – JSON-LD context array (required)
  /// [type] – Types array (must include `'VerifiablePresentation'`)
  /// [holder] – Identifier for the presenter (optional)
  /// [verifiableCredential] – List of embedded credentials (optional)
  /// [proof] – Cryptographic proof (optional)
  VpDataModelV1({
    required this.context,
    this.id,
    required this.type,
    this.holder,
    List<VerifiableCredential>? verifiableCredential,
    Map<String, dynamic>? proof,
  })  : verifiableCredential = verifiableCredential ?? [],
        proof = proof ?? {};

  /// Converts the VP object to a JSON-compliant `Map`
  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json['@context'] = context;
    if (id != null) json['id'] = id;
    json['type'] = type;
    if (holder != null) json['holder'] = holder;

    if (verifiableCredential.isNotEmpty) {
      json['verifiableCredential'] =
          verifiableCredential.map((vc) => vc.toJson()).toList();
    }

    if (proof.isNotEmpty) {
      json['proof'] = proof;
    }

    return json;
  }

  /// Creates a [VpDataModelV1] from JSON or a JSON-like input
  ///
  /// [input] can be a JSON string or a `Map<String, dynamic>`.
  /// Validates and parses mandatory and optional fields.
  VpDataModelV1.fromJson(dynamic input)
      : context = [],
        type = [],
        verifiableCredential = [],
        proof = {} {
    final json = jsonToMap(input);

    context = getStringList(json, '@context', mandatory: true);
    id = getString(json, 'id');
    type = getStringList(
      json,
      'type',
      allowSingleValue: true,
      mandatory: true,
    );
    holder = getString(json, 'holder');

    // Handles both single VC or a list of VCs
    final credentials = json['verifiableCredential'];
    if (credentials != null) {
      if (credentials is List) {
        verifiableCredential = credentials
            .map((e) => MutableVcDataModelV1.fromJson(jsonToMap(e)))
            .toList();
      } else if (credentials is Map) {
        verifiableCredential = [
          MutableVcDataModelV1.fromJson(jsonToMap(credentials))
        ];
      }
    }

    // Parse proof object if present
    if (json['proof'] != null && json['proof'] is Map) {
      proof = Map.of(json['proof'] as Map<String, dynamic>);
    }
  }
}
