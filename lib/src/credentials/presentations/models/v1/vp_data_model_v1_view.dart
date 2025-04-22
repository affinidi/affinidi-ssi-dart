import '../../../models/holder.dart';
import '../../../models/parsed_vc.dart';
import '../../../models/proof.dart';
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
abstract interface class VpDataModelV1 implements VerifiablePresentation {
  /// The JSON-LD context for this presentation.
  ///
  /// Typically includes 'https://www.w3.org/2018/credentials/v1'.
  @override
  List<String> get context;

  /// The optional identifier for this presentation.
  @override
  String? get id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  @override
  List<String> get type;

  /// The entity presenting the credentials.
  ///
  /// Typically identified by a DID.
  @override
  Holder? get holder;

  /// The list of verifiable credentials embedded in this presentation.
  @override
  List<ParsedVerifiableCredential> get verifiableCredential;

  /// The cryptographic proof created by the holder.
  Proof get proof;
}
