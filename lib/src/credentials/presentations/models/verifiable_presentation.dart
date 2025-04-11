import 'package:ssi/src/credentials/models/doc_with_embedded_proof.dart';
import 'package:ssi/src/credentials/models/verifiable_credential.dart';

/// Abstract base class for a Verifiable Presentation (VP).
///
/// This interface defines common fields and behaviors for VP models,
/// including both W3C VC Data Model v1.1 and v2.0 presentations.
///
/// Implementations such as [VpDataModelV1] and [VpDataModelV2]
/// should conform to this interface.
abstract interface class VerifiablePresentation extends DocWithEmbeddedProof {
  /// Returns the VerifiableCredential issuer
  List<String> get context;

  /// Returns the VerifiableCredential id.
  String? get id;

  /// Returns a list of VerifiableCredential types.
  // FIXME should be changed to a Set
  List<String> get type;
  
  /// Optional DID or URI of the holder who generated the presentation.
  String? get holder;

  /// One or more verifiable credentials included in this presentation.
  List<VerifiableCredential> get verifiableCredential;

  @override
  VerifiablePresentation.fromJson(super.input) : super.fromJson();
}
