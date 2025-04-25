import '../../../models/field_types/holder.dart';
import '../../../models/parsed_vc.dart';
import '../../../proof/embedded_proof.dart';
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
class MutableVpDataModelV1 extends VpDataModelV1 {
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

  /// Creates a [VpDataModelV1] instance.
  ///
  /// The [context] is the JSON-LD context array (required).
  /// The [type] is an array that must include 'VerifiablePresentation'.
  /// The [holder] is an identifier for the presenter (optional).
  /// The [verifiableCredential] is a list of embedded credentials (optional).
  /// The [proof] is a cryptographic proof (optional).
  MutableVpDataModelV1({
    List<String>? context,
    this.id,
    Set<String>? type,
    this.holder,
    List<ParsedVerifiableCredential>? verifiableCredential,
    List<EmbeddedProof>? proof,
  })  : context = context ?? [],
        type = type ?? {},
        proof = proof ?? [],
        verifiableCredential = verifiableCredential ?? [];
}
