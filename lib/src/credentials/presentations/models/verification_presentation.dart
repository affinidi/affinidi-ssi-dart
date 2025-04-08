import 'package:ssi/src/credentials/models/verifiable_credential.dart';

/// Abstract base class for a Verifiable Presentation (VP).
///
/// This interface defines common fields and behaviors for VP models,
/// including both W3C VC Data Model v1.1 and v2.0 presentations.
///
/// Implementations such as [VpDataModelV1] and [VpDataModelV2]
/// should conform to this interface.
abstract interface class VerificationPresentation {
  /// Optional DID or URI of the holder who generated the presentation.
  String? get holder;

  /// One or more verifiable credentials included in this presentation.
  List<VerifiableCredential> get verifiableCredential;

  /// Returns a JSON-serializable representation of the presentation.
  Map<String, dynamic> toJson();
}
