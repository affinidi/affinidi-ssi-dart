import '../../ssi.dart';

/// Represents an SSI exception.
class SsiException implements Exception {
  /// The exception message.
  final String message;

  /// The exception code.
  final String code;

  /// The original message, if any.
  final String? originalMessage;

  /// Creates a [SsiException] instance.
  SsiException({
    required this.message,
    required this.code,
    this.originalMessage,
  });

  @override
  String toString() {
    var result = 'SsiException: $message (code: $code)';
    if (originalMessage != null) {
      result += ' [original: $originalMessage]';
    }
    return result;
  }
}

/// Exception thrown during DID resolution operations.
///
/// This specialized exception is used when DID resolution fails for any reason.
/// It extends [SsiException] to provide additional context specific to DID
/// resolution errors, such as detailed error information about why the
/// resolution failed.
///
/// Common scenarios where this exception is thrown include:
/// - DID not found (the DID does not exist)
/// - Invalid DID format
/// - Network errors when fetching DID documents
/// - DID method not supported
/// - DID document validation failures
/// - DID has been deactivated
///
/// Example:
/// ```dart
/// try {
///   final didDoc = await resolver.resolve('did:example:123');
/// } on SsiDidResolutionException catch (e) {
///   print('Resolution failed: ${e.message}');
///   print('Resolution metadata: ${e.resolutionMetadata}');
/// }
/// ```
class SsiDidResolutionException extends SsiException {
  /// Additional detailed information about the resolution error.
  ///
  /// This field can contain method-specific error information, stack traces,
  /// or other diagnostic details that provide more context about why the
  /// DID resolution failed. It may be null if no additional details are available.
  final DidResolutionMetadata? resolutionMetadata;

  /// Creates a [SsiDidResolutionException] instance.
  ///
  /// Parameters:
  /// - [message]: A human-readable description of the error
  /// - [code]: An error code identifying the type of error
  /// - [originalMessage]: The original error message from the underlying system, if any
  /// - [resolutionMetadata]: Additional diagnostic information about the error
  SsiDidResolutionException({
    required super.message,
    required super.code,
    super.originalMessage,
    this.resolutionMetadata,
  });
}
