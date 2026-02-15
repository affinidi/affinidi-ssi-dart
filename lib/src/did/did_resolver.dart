import 'dart:typed_data';

import '../exceptions/ssi_exception.dart';
import 'did_document/index.dart';

/// Interface for resolving DID documents.
///
/// This interface defines the contract for DID resolution implementations.
abstract interface class DidResolver {
  /// Resolves a DID Document for the given [did].
  ///
  /// [did] must be a valid DID string.
  ///
  /// Returns a [DidDocument] containing the resolved DID document.
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  Future<DidDocument> resolveDid(String did
  //,[DidResolutionOptions? options]
  );
}



/// Metadata about a DID Document.
///
/// Contains metadata properties about the DID Document as defined by the
/// W3C DID Core specification. This may include information such as:
/// - `created`: Timestamp of when the DID was created
/// - `updated`: Timestamp of the last update to the DID Document
/// - `deactivated`: Boolean indicating if the DID has been deactivated
/// - `versionId`: Identifier for the specific version of the DID Document
/// - `nextUpdate`: Timestamp of when the next update is expected
/// - `nextVersionId`: Identifier for the next version
///
/// The exact properties depend on the DID method specification.
typedef DidDocumentMetadata = Map<String, dynamic>;

/// Metadata about the DID resolution process.
///
/// Contains information about the resolution process itself, as defined by the
/// W3C DID Core specification. This typically includes:
/// - `contentType`: The media type of the resolved DID document
/// - `error`: Error code if resolution failed (e.g., 'notFound', 'invalidDid')
/// - `message`: Human-readable error message if resolution failed
///
/// Additional properties may be included depending on the resolution implementation.
typedef DidResolutionMetadata = Map<String, dynamic>;

/// Options for DID resolution.
///
/// Specifies parameters that control how a DID is resolved. Common options include:
/// - `accept`: Preferred media type for the DID document representation
///   (e.g., 'application/did+json', 'application/did+ld+json')
/// - `versionId`: Request a specific version of the DID Document
/// - `versionTime`: Request the DID Document as it existed at a specific time
/// - `versionNumber`: Request a specific version number
/// - `hl`: Hash link for verifying DID document integrity
/// - `service`: Service endpoint identifier to dereference
/// - `relativeRef`: Relative reference within the DID Document
///
/// The supported options depend on the specific DID method and resolver implementation.
typedef DidResolutionOptions = Map<String, dynamic>;

/// Binary stream representation of a DID Document.
///
/// Represents the DID document in its raw byte format, preserving the exact
/// serialization as received or generated. This is particularly useful for:
/// - Cryptographic verification where byte-exact representation is required
/// - Preserving original formatting and whitespace
/// - Supporting various serialization formats (JSON, JSON-LD, CBOR, etc.)
///
/// The format of the bytes is determined by the `contentType` in the
/// [DidResolutionMetadata].
typedef DidDocumentStream = Uint8List;

/// Interface for resolving DID documents.
///
/// This interface defines the contract for DID resolution implementations.
///
abstract interface class DidResolverV2 {
  /// Resolves a DID Document for the given [did].
  ///
  /// [did] must be a valid DID string.
  ///
  /// Returns a [DidDocument] containing the resolved DID document.
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  Future<(DidDocument, DidDocumentMetadata?, DidResolutionMetadata?)> resolve(
      String did, [DidResolutionOptions? options]);

  /// Resolves a DID to its representation (document stream) for the given [did].
  ///
  /// This method returns the DID document in its requested representation format
  /// as a stream, which is useful when you need the exact bytes of the document
  /// for cryptographic verification or when preserving the original format is required.
  ///
  /// [did] must be a valid DID string.
  /// [options] specifies resolution options such as accept format preferences.
  ///
  /// Returns a tuple containing:
  /// - [DidDocumentStream]: The DID document in its requested representation format
  /// - [DidDocumentMetadata]: Metadata about the DID document
  /// - [DidResolutionMetadata]: Metadata about the resolution process
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  /// - The requested representation format is not supported
  Future<(DidDocumentStream, DidDocumentMetadata?, DidResolutionMetadata?)>
      resolveRepresentation(String did, [DidResolutionOptions? options]);
}
