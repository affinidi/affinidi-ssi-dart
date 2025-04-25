import '../../../../util/json_util.dart';
import '../../../models/field_types/holder.dart';
import '../../../models/field_types/terms_of_use.dart';
import '../../../models/parsed_vc.dart';
import '../../../proof/embedded_proof.dart';
import '../vc_parse_present.dart';
import '../verifiable_presentation.dart';

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
abstract class VpDataModelV2 implements VerifiablePresentation {
  static const String contextUrl = 'https://www.w3.org/ns/credentials/v2';

  /// The JSON-LD context for this presentation.
  ///
  /// Must include 'https://www.w3.org/ns/credentials/v2'.
  @override
  List<String> get context;

  /// The unique identifier for this presentation.
  @override
  Uri? get id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  @override
  Set<String> get type;

  /// The entity presenting the credentials.
  ///
  /// Usually identified by a DID.
  @override
  Holder? get holder;

  /// The terms of use describing conditions for credential usage.
  List<TermsOfUse> get termsOfUse;

  /// The verifiable credentials included in this presentation.
  @override
  List<ParsedVerifiableCredential> get verifiableCredential;

  /// The cryptographic proof securing this presentation.
  ///
  /// Can be a DataIntegrityProof, JWT, or other proof format.
  @override
  List<EmbeddedProof> get proof;

  /// Converts this presentation to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.id.key] = id?.toString();
    json[_P.type.key] = type.toList();
    json[_P.holder.key] = holder?.toJson();
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    json[_P.verifiableCredential.key] =
        verifiableCredential.map(presentVC).toList();

    return json;
  }
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
