import '../../../../ssi.dart';
import '../../models/doc_with_embedded_proof.dart';

/// Abstract base class for a Verifiable Presentation (VP).
///
/// This interface defines common fields and behaviors for VP models,
/// including both W3C VC Data Model v1.1 and v2.0 presentations.
///
/// Implementations such as [VpDataModelV1] and [VpDataModelV2]
/// should conform to this interface.
abstract interface class VerifiablePresentation
    implements DocWithEmbeddedProof {
  /// The context that defines the schema for this presentation.
  List<String> get context;

  /// The unique identifier for this presentation.
  String? get id;

  /// The types describing the structure of this presentation.
  // FIXME(FTL-20738) should be changed to a Set
  List<String> get type;

  /// The DID or URI of the holder who generated this presentation.
  String? get holder;

  /// The verifiable credentials included in this presentation.
  List<VerifiableCredential> get verifiableCredential;

  /// Creates a [VerifiablePresentation] from a JSON map.
  @override
  VerifiablePresentation.fromJson(Map<String, dynamic> input);

  /// Converts this presentation to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson();
}
