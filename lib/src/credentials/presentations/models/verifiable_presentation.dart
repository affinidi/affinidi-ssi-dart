import '../../models/doc_with_embedded_proof.dart';
import '../../models/field_types/holder.dart';
import '../../models/parsed_vc.dart';

/// Abstract base class for a Verifiable Presentation (VP).
///
/// This interface defines common fields and behaviors for VP models,
/// including both W3C VC Data Model v1.1 and v2.0 presentations.
///
/// Implementations such as VpDataModelV1 and VpDataModelV2
/// should conform to this interface.
abstract interface class VerifiablePresentation
    implements DocWithEmbeddedProof {
  /// The context that defines the schema for this presentation.
  List<String> get context;

  /// The unique identifier for this presentation.
  Uri? get id;

  /// The types describing the structure of this presentation.
  Set<String> get type;

  /// The entity that is presenting these credentials.
  Holder get holder;

  /// The verifiable credentials included in this presentation.
  List<ParsedVerifiableCredential> get verifiableCredential;

  /// Converts this presentation to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson();
}
