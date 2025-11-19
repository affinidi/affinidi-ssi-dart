import 'dart:collection';

import '../../../../../ssi.dart';
import '../../../../util/json_util.dart';
import '../../../models/field_types/context.dart';
import '../vc_parse_present.dart';

part './mutable_vp_data_model_v1.dart';

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
  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  @override
  final JsonLdContext context;

  /// The optional identifier for this presentation.
  @override
  Uri? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  @override
  final UnmodifiableSetView<String> type;

  /// The identifier of the holder presenting the credentials.
  ///
  /// Typically a DID.
  @override
  Holder holder;

  /// The list of verifiable credentials embedded in this presentation.
  @override
  final UnmodifiableListView<ParsedVerifiableCredential> verifiableCredential;

  /// The cryptographic proof(s) created by the holder.
  @override
  final UnmodifiableListView<EmbeddedProof> proof;

  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context.toJson();
    json[_P.id.key] = id?.toString();
    json[_P.type.key] = type.toList();
    json[_P.holder.key] = holder.toJson();
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.verifiableCredential.key] =
        verifiableCredential.map(presentVC).toList();

    return cleanEmpty(json);
  }

  /// Validates the essential Verifiable Presentation properties (`context`, `type`).
  ///
  /// Ensures [context] is not empty and starts with [dmV1ContextUrl],
  /// and that [type] is not empty.
  ///
  /// Throws [SsiException] if validation fails. Returns `true` if valid.
  bool validate() {
    if (context.firstUri.toString() != dmV1ContextUrl) {
      throw SsiException(
        message:
            'The first URI of `${_P.context.key}` property should always be $dmV1ContextUrl',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (type.isEmpty) {
      throw SsiException(
        message: '`${_P.type.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (proof.length > 1) {
      throw SsiException(
        message: 'Multiple proofs are not supported',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    return true;
  }

  /// Creates a [VpDataModelV1] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [type] is an array that must include 'VerifiablePresentation'.
  /// The [holder] is an identifier for the presenter (optional).
  /// The [verifiableCredential] is a list of embedded credentials (optional).
  /// The [proof] is a cryptographic proof (optional).
  VpDataModelV1({
    required this.context,
    this.id,
    required Set<String> type,
    required this.holder,
    required List<ParsedVerifiableCredential> verifiableCredential,
    required List<EmbeddedProof> proof,
  })  : type = UnmodifiableSetView(type),
        verifiableCredential = UnmodifiableListView(verifiableCredential),
        proof = UnmodifiableListView(proof) {
    validate();
  }

  /// Creates a [VpDataModelV1] from JSON input.
  ///
  /// The [input] can be a JSON string or a [Map<String, dynamic>].
  /// Parses both mandatory and optional fields.
  factory VpDataModelV1.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = JsonLdContext.fromJson(json[_P.context.key]);

    final id = getUri(json, _P.id.key);
    final type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    ).toSet();

    final holder = Holder.fromJson(json[_P.holder.key]);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentials = parseListOrSingleItem<ParsedVerifiableCredential>(
        json, _P.verifiableCredential.key, parseVC,
        allowSingleValue: true);

    return VpDataModelV1(
        context: context,
        id: id,
        type: type,
        proof: proof,
        holder: holder,
        verifiableCredential: credentials);
  }

  /// Creates a new [VpDataModelV1] instance as a deep copy of the provided [input].
  ///
  /// This constructor initializes a new object with the same values as the
  /// properties of the [input] `VpDataModelV1` instance.
  VpDataModelV1.clone(VpDataModelV1 input)
      : this(
            context: input.context,
            id: input.id,
            type: input.type,
            holder: input.holder,
            verifiableCredential: input.verifiableCredential,
            proof: input.proof);

  /// Creates a [VpDataModelV1] instance from a mutable model.
  ///
  /// The [data] is a mutable VP data model.
  factory VpDataModelV1.fromMutable(MutableVpDataModelV1 data) =>
      VpDataModelV1.fromJson(data.toJson());
}
