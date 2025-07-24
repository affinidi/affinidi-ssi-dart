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
  Future<DidDocument> resolve(String did);
}
