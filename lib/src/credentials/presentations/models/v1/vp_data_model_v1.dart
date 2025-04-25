import '../../../../util/json_util.dart';
import '../../../models/field_types/holder.dart';
import '../../../models/parsed_vc.dart';
import '../../../proof/embedded_proof.dart';
import '../vc_parse_present.dart';
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
abstract class VpDataModelV1 implements VerifiablePresentation {
  /// The default JSON-LD context URL for VP v1
  static const String contextUrl = 'https://www.w3.org/2018/credentials/v1';

  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  @override
  List<String> get context;

  /// The optional identifier for this presentation.
  @override
  Uri? get id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  @override
  Set<String> get type;

  /// The entity presenting the credentials.
  ///
  /// Typically identified by a DID.
  @override
  Holder? get holder;

  /// The list of verifiable credentials embedded in this presentation.
  @override
  List<ParsedVerifiableCredential> get verifiableCredential;

  /// The cryptographic proof created by the holder.
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
    json[_P.verifiableCredential.key] =
        verifiableCredential.map(presentVC).toList();

    return json;
  }
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
