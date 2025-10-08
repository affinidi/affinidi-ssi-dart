part of 'vp_data_model_v1.dart';

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
class MutableVpDataModelV1 {
  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  MutableJsonLdContext? context;

  /// The optional identifier for this presentation.
  Uri? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  Set<String> type;

  /// The identifier of the holder presenting the credentials.
  ///
  /// Typically a DID.
  MutableHolder? holder;

  /// The list of verifiable credentials embedded in this presentation.
  List<ParsedVerifiableCredential> verifiableCredential;

  /// The cryptographic proof(s) created by the holder.
  List<EmbeddedProof> proof;

  /// Returns the JSON representation of the MutableVpDataModelV1.
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context?.toJson();
    json[_P.id.key] = id?.toString();
    json[_P.type.key] = type.toList();
    json[_P.holder.key] = holder?.toJson();
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.verifiableCredential.key] =
        verifiableCredential.map(presentVC).toList();

    return cleanEmpty(json);
  }

  /// Creates a [VpDataModelV1] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [type] is an array that must include 'VerifiablePresentation'.
  /// The [holder] is an identifier for the presenter (optional).
  /// The [verifiableCredential] is a list of embedded credentials (optional).
  /// The [proof] is a cryptographic proof (optional).
  MutableVpDataModelV1({
    this.context,
    this.id,
    Set<String>? type,
    this.holder,
    List<ParsedVerifiableCredential>? verifiableCredential,
    List<EmbeddedProof>? proof,
  })  : type = type ?? {},
        proof = proof ?? [],
        verifiableCredential = verifiableCredential ?? [];

  /// Creates a [VpDataModelV1] from JSON input.
  ///
  /// The [input] can be a JSON string or a [Map<String, dynamic>].
  /// Parses both mandatory and optional fields.
  factory MutableVpDataModelV1.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = MutableJsonLdContext.fromJson(json[_P.context.key]);
    final id = getUri(json, _P.id.key);
    final type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
    ).toSet();

    final holder = MutableHolder.fromJson(json[_P.holder.key]);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentials = parseListOrSingleItem<ParsedVerifiableCredential>(
        json, _P.verifiableCredential.key, parseVC,
        allowSingleValue: true);

    return MutableVpDataModelV1(
        context: context,
        id: id,
        type: type,
        proof: proof,
        holder: holder,
        verifiableCredential: credentials);
  }
}

typedef _P = VpDataModelV1Key;

/// Defines the keys for accessing properties within the [MutableVpDataModelV1] data model.
enum VpDataModelV1Key {
  /// The JSON-LD context key (`@context`).
  context(key: '@context'),

  /// The identifier key (`id`).
  id,

  /// The type key (`type`).
  type,

  /// The holder key (`holder`).
  holder,

  /// The verifiable credential key (`verifiableCredential`).
  verifiableCredential,

  /// The cryptographic proof key (`proof`).
  proof;

  final String? _key;

  /// Returns the key string (custom or enum name).
  String get key => _key ?? name;

  const VpDataModelV1Key({String? key}) : _key = key;
}
