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
    required String message,
    this.failedUri,
    this.cause,
    this.operation,
  }) : super(
          message: message,
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

/// Exception thrown when a remote context fails to load.
class RemoteContextLoadException extends JsonLdException {
  RemoteContextLoadException({
    required Uri uri,
    required Object cause,
  }) : super(
          message: 'Failed to load remote context',
          failedUri: uri,
          cause: cause,
          operation: 'load_remote_context',
        );
}
