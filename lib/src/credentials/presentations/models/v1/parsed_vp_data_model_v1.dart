import '../../../../../ssi.dart';
import '../../../../util/json_util.dart';
import '../../../models/field_types/holder.dart';
import '../../../models/parsed_vc.dart';
import '../../../proof/embedded_proof.dart';
import '../vc_parse_present.dart';
import 'vp_data_model_v1.dart';

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
class ParsedVpDataModelV1 extends VpDataModelV1 {
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
  ParsedHolder holder;

  /// The list of verifiable credentials embedded in this presentation.
  @override
  List<ParsedVerifiableCredential> verifiableCredential;

  /// The cryptographic proof(s) created by the holder.
  @override
  List<EmbeddedProof> proof;

  /// Creates a [VpDataModelV1] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [type] is an array that must include 'VerifiablePresentation'.
  /// The [holder] is an identifier for the presenter (optional).
  /// The [verifiableCredential] is a list of embedded credentials (optional).
  /// The [proof] is a cryptographic proof (optional).
  ParsedVpDataModelV1._({
    required this.context,
    this.id,
    required this.type,
    required this.holder,
    required this.verifiableCredential,
    required this.proof,
  });

  /// Creates a [VpDataModelV1] from JSON input.
  ///
  /// The [input] can be a JSON string or a [Map<String, dynamic>].
  /// Parses both mandatory and optional fields.
  factory ParsedVpDataModelV1.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key, mandatory: true);
    if (context.isEmpty || context.first != VpDataModelV1.contextUrl) {
      throw SsiException(
        message:
            'The first URI of @context property should always be ${VpDataModelV1.contextUrl}',
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

    final holder = ParsedHolder.fromJson(json[_P.holder.key]);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentials = parseListOrSingleItem<ParsedVerifiableCredential>(
        json, _P.verifiableCredential.key, parseVC,
        allowSingleValue: true);

    return ParsedVpDataModelV1._(
        context: context,
        id: id,
        type: type,
        proof: proof,
        holder: holder,
        verifiableCredential: credentials);
  }
}

typedef _P = VpDataModelV1Key;
