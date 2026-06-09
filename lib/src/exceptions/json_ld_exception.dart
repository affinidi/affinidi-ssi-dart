import 'ssi_exception.dart';
import 'ssi_exception_type.dart';

/// Exception thrown during JSON-LD processing operations.
class JsonLdException extends SsiException {
  /// The URI that failed to load (if applicable).
  final Uri? failedUri;

  /// The underlying error that caused this exception.
  final Object? cause;

  /// The operation that failed.
  final String? operation;

  JsonLdException({
    required super.message,
    this.failedUri,
    this.cause,
    this.operation,
  }) : super(
          code: SsiExceptionType.jsonLdProcessing.code,
        );

  @override
  String toString() {
    final buffer = StringBuffer('JsonLdException: $message');
    if (operation != null) {
      buffer.write(' (operation: $operation)');
    }
    if (failedUri != null) {
      buffer.write(' (URI: $failedUri)');
    }
    if (cause != null) {
      buffer.write(' (cause: $cause)');
    }
    return buffer.toString();
  }
}
