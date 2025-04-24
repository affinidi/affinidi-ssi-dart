import 'package:ssi/src/credentials/models/vc_models.dart';

import '../../../models/holder.dart';
import '../../../models/parsed_vc.dart';
import '../../../proof/embedded_proof.dart';
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
abstract interface class VpDataModelV2 implements VerifiablePresentation {
  /// The JSON-LD context for this presentation.
  ///
  /// Must include 'https://www.w3.org/ns/credentials/v2'.
  @override
  List<String> get context;

  /// The unique identifier for this presentation.
  @override
  String? get id;

  /// The type definitions for this presentation.
  ///
  /// Must include 'VerifiablePresentation'.
  @override
  List<String> get type;

  /// The entity presenting the credentials.
  ///
  /// Usually identified by a DID.
  @override
  Holder? get holder;

  /// The terms of use describing conditions for credential usage.
  List<TermOfUse> get termsOfUse;

  /// The verifiable credentials included in this presentation.
  @override
  List<ParsedVerifiableCredential> get verifiableCredential;

  /// The cryptographic proof securing this presentation.
  ///
  /// Can be a DataIntegrityProof, JWT, or other proof format.
  @override
  List<EmbeddedProof> get proof;
}
