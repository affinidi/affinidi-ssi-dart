part of 'vp_data_model_v2.dart';

/// Represents a Verifiable Presentation (VP) according to the W3C VC Data Model v1.1.
///
/// A Verifiable Presentation is a container for one or more Verifiable Credentials (VCs),
/// optionally including a `proof` issued by the `holder`.
///
/// This class supports JSON serialization and deserialization for interoperability.
///
/// Example:
/// ```dart
/// final vp = VpDataModelV2(
///   context: ['https://www.w3.org/2018/credentials/v1'],
///   type: ['VerifiablePresentation'],
///   holder: 'did:example:holder',
///   verifiableCredential: [vc],
/// );
/// ```
class MutableVpDataModelV2 extends _VpDataModelV2 {
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
  MutableHolder? holder;

  /// The list of verifiable credentials embedded in this presentation.
  @override
  List<ParsedVerifiableCredential> verifiableCredential;

  /// The cryptographic proof(s) created by the holder.
  @override
  List<EmbeddedProof> proof;

  @override
  List<TermsOfUse> termsOfUse;

  /// Creates a [MutableVpDataModelV2] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [type] is an array that must include 'VerifiablePresentation'.
  /// The [holder] is an identifier for the presenter (optional).
  /// The [verifiableCredential] is a list of embedded credentials (optional).
  /// The [proof] is a cryptographic proof (optional).
  MutableVpDataModelV2({
    List<String>? context,
    this.id,
    Set<String>? type,
    this.holder,
    List<ParsedVerifiableCredential>? verifiableCredential,
    List<EmbeddedProof>? proof,
    List<TermsOfUse>? termsOfUse,
  })  : context = context ?? [],
        type = type ?? {},
        proof = proof ?? [],
        termsOfUse = termsOfUse ?? [],
        verifiableCredential = verifiableCredential ?? [];
}

abstract class _VpDataModelV2 {
  /// The JSON-LD context for this presentation.
  ///
  /// Must include 'https://www.w3.org/ns/credentials/v2'.
  List<String> get context;

  /// The unique identifier for this presentation.
  Uri? get id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  Set<String> get type;

  /// The entity presenting the credentials.
  ///
  /// Usually identified by a DID.
  MutableHolder? get holder;

  /// The terms of use describing conditions for credential usage.
  List<TermsOfUse> get termsOfUse;

  /// The verifiable credentials included in this presentation.
  List<ParsedVerifiableCredential> get verifiableCredential;

  /// The cryptographic proof securing this presentation.
  ///
  /// Can be a DataIntegrityProof, JWT, or other proof format.
  List<EmbeddedProof> get proof;

  /// Converts this presentation to a JSON-serializable map.
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
