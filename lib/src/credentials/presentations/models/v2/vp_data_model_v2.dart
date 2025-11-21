import 'dart:collection';

import '../../../../../ssi.dart';
import '../../../../util/json_util.dart';
import '../vc_parse_present.dart';

part 'mutable_vp_data_model_v2.dart';

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
class VpDataModelV2 implements VerifiablePresentation {
  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  @override
  final UnmodifiableListView<String> context;

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

  /// The list of termsOfUse under which this presentations is issued
  final UnmodifiableListView<TermsOfUse> termsOfUse;

  /// Converts this presentation to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.id.key] = id?.toString();
    json[_P.type.key] = type.toList();
    json[_P.holder.key] = holder.toJson();
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    json[_P.verifiableCredential.key] =
        verifiableCredential.map(presentVC).toList();

    return cleanEmpty(json);
  }

  /// Validates the essential Verifiable Presentation properties (`context`, `type`).
  ///
  /// Ensures [context] is not empty and starts with [dmV2ContextUrl],
  /// and that [type] is not empty.
  ///
  /// Also validates that all verifiable credentials are compatible with V2 presentations:
  /// - SD-JWT VCs are supported (automatically enveloped per W3C spec)
  /// - JSON-LD VCs (V1 and V2) are supported
  /// - JWT VCs are NOT supported (use V1 presentations for JWT VCs)
  ///
  /// Throws [SsiException] if validation fails. Returns `true` if valid.
  bool validate() {
    if (context.isEmpty) {
      throw SsiException(
        message: '`${_P.context.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (context.first != dmV2ContextUrl) {
      throw SsiException(
        message:
            'The first URI of `${_P.context.key}` property should always be $dmV2ContextUrl',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (type.isEmpty) {
      throw SsiException(
        message: '`${_P.type.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    // Validate credential compatibility with V2 presentations
    _validateCredentialCompatibility();

    return true;
  }

  /// Validates that all credentials in this V2 presentation are compatible.
  ///
  /// V2 presentations support:
  /// - SD-JWT VCs (SdJwtDataModelV2) - automatically enveloped
  /// - JSON-LD VCs (LdVcDataModelV1, LdVcDataModelV2)
  ///
  /// V2 presentations do NOT support:
  /// - JWT VCs (JwtVcDataModelV1) - causes JSON-LD context conflicts
  ///
  /// Throws [SsiException] if incompatible credentials are found.
  void _validateCredentialCompatibility() {
    for (final credential in verifiableCredential) {
      // Check for JWT VC (not SD-JWT)
      if (credential.runtimeType.toString() == 'JwtVcDataModelV1') {
        throw SsiException(
          message:
              'JWT VCs (JwtVcDataModelV1) are not compatible with V2 presentations. '
              'JWT VCs contain V1 context which conflicts with V2 presentation context during JSON-LD processing. '
              'Use V1 presentations (VpDataModelV1) for JWT VCs, or use SD-JWT VCs (SdJwtDataModelV2) with V2 presentations.',
          code: SsiExceptionType.invalidVC.code,
        );
      }
    }
  }

  /// Creates a [VpDataModelV2] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [type] is an array that must include 'VerifiablePresentation'.
  /// The [holder] is an identifier for the presenter (optional).
  /// The [verifiableCredential] is a list of embedded credentials (optional).
  /// The [proof] is a cryptographic proof (optional).
  VpDataModelV2(
      {required List<String> context,
      this.id,
      required Set<String> type,
      required this.holder,
      required List<ParsedVerifiableCredential> verifiableCredential,
      required List<EmbeddedProof> proof,
      List<TermsOfUse>? termsOfUse})
      : context = UnmodifiableListView(context),
        type = UnmodifiableSetView(type),
        verifiableCredential = UnmodifiableListView(verifiableCredential),
        proof = UnmodifiableListView(proof),
        termsOfUse = UnmodifiableListView(termsOfUse ?? []) {
    validate();
  }

  /// Creates a [VpDataModelV2] from JSON input.
  ///
  /// The [input] can be a JSON string or a [Map<String, dynamic>].
  /// Parses both mandatory and optional fields.
  factory VpDataModelV2.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key, mandatory: true);

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

    final termsOfUse = parseListOrSingleItem<TermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => TermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return VpDataModelV2(
        context: context,
        id: id,
        type: type,
        proof: proof,
        holder: holder,
        verifiableCredential: credentials,
        termsOfUse: termsOfUse);
  }

  /// Creates a new [VpDataModelV2] instance as a deep copy of the provided [input].
  ///
  /// This constructor initializes a new object with the same values as the
  /// properties of the [input] `VpDataModelV2` instance.
  VpDataModelV2.clone(VpDataModelV2 input)
      : this(
            context: input.context,
            id: input.id,
            type: input.type,
            holder: input.holder,
            verifiableCredential: input.verifiableCredential,
            proof: input.proof,
            termsOfUse: input.termsOfUse);

  /// Creates a [VpDataModelV2] instance from a mutable model.
  ///
  /// The [data] is a mutable VP data model.
  factory VpDataModelV2.fromMutable(MutableVpDataModelV2 data) =>
      VpDataModelV2.fromJson(data.toJson());
}
