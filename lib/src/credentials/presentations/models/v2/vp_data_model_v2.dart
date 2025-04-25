import '../../../../../ssi.dart';
import '../../../../util/json_util.dart';
import '../../../models/field_types/holder.dart';
import '../../../models/field_types/terms_of_use.dart';
import '../../../models/parsed_vc.dart';
import '../../../proof/embedded_proof.dart';
import '../vc_parse_present.dart';
import '../verifiable_presentation.dart';

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
class VpDataModelV2 extends _VpDataModelV2 implements VerifiablePresentation {
  static const String contextUrl = 'https://www.w3.org/ns/credentials/v2';

  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  @override
  List<String> context;

  /// The optional identifier for this presentation.
  @override
  Uri? id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  @override
  Set<String> type;

  /// The identifier of the holder presenting the credentials.
  ///
  /// Typically a DID.
  @override
  Holder holder;

  /// The list of verifiable credentials embedded in this presentation.
  @override
  List<ParsedVerifiableCredential> verifiableCredential;

  /// The cryptographic proof(s) created by the holder.
  @override
  List<EmbeddedProof> proof;

  @override
  List<TermsOfUse> termsOfUse;

  /// Creates a [VpDataModelV2] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [type] is an array that must include 'VerifiablePresentation'.
  /// The [holder] is an identifier for the presenter (optional).
  /// The [verifiableCredential] is a list of embedded credentials (optional).
  /// The [proof] is a cryptographic proof (optional).
  VpDataModelV2._(
      {required this.context,
      this.id,
      required this.type,
      required this.holder,
      required this.verifiableCredential,
      required this.proof,
      List<TermsOfUse>? termsOfUse})
      : termsOfUse = termsOfUse ?? [];

  VpDataModelV2(VpDataModelV2 input)
      : this._(
            context: input.context,
            id: input.id,
            type: input.type,
            holder: input.holder,
            verifiableCredential: input.verifiableCredential,
            proof: input.proof,
            termsOfUse: input.termsOfUse);

  /// Creates a [VpDataModelV2] from JSON input.
  ///
  /// The [input] can be a JSON string or a [Map<String, dynamic>].
  /// Parses both mandatory and optional fields.
  factory VpDataModelV2.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key, mandatory: true);
    if (context.isEmpty || context.first != contextUrl) {
      throw SsiException(
        message:
            'The first URI of @context property should always be $contextUrl',
        code: SsiExceptionType.invalidJson.code,
      );
    }

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

    return VpDataModelV2._(
        context: context,
        id: id,
        type: type,
        proof: proof,
        holder: holder,
        verifiableCredential: credentials,
        termsOfUse: termsOfUse);
  }
}
