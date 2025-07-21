import '../exceptions/ssi_exception.dart';
import 'did_document/index.dart';

/// Interface for resolving DID documents.
///
/// This interface defines the contract for DID resolution implementations.
/// Implementations may choose to ignore the `resolverAddress` parameter if
/// they have their own resolution logic or configuration.
abstract interface class DidResolver {
  /// Resolves a DID Document for the given [did].
  ///
  /// [did] must be a valid DID string.
  /// [resolverAddress] is the URL of a universal resolver service (optional).
  /// Some implementations may ignore this parameter if they have built-in
  /// resolution capabilities or are configured with a specific resolver.
  ///
  /// Returns a [DidDocument] containing the resolved DID document.
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  /// - The resolver address is required but not provided
  Future<DidDocument> resolve(
    String did, {
    String? resolverAddress,
  });
}
