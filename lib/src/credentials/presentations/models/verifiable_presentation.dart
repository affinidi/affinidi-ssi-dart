import 'package:ssi/src/credentials/models/verifiable_credential.dart';
import 'package:ssi/src/credentials/models/verifiable_data.dart';

/// Abstract base class for a Verifiable Presentation (VP).
///
/// This interface defines common fields and behaviors for VP models,
/// including both W3C VC Data Model v1.1 and v2.0 presentations.
///
/// Implementations such as [VpDataModelV1] and [VpDataModelV2]
/// should conform to this interface.
abstract interface class VerifiablePresentation extends VerifiableData {
  /// Optional DID or URI of the holder who generated the presentation.
  String? get holder;

  /// One or more verifiable credentials included in this presentation.
  List<VerifiableCredential> get verifiableCredential;

  @override
  VerifiablePresentation.fromJson(super.input) : super.fromJson();
}
