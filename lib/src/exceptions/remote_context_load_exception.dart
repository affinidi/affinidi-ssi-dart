import 'dart:async';

import 'json_ld_exception.dart';

/// Exception thrown when a remote context fails to load.
class RemoteContextLoadException extends JsonLdException {
  /// Creates a [RemoteContextLoadException] from a loading error.
  factory RemoteContextLoadException({
    required Uri uri,
    required Object cause,
  }) {
    if (cause is RemoteContextLoadException) {
      return cause;
    }

    if (cause is TimeoutException) {
      return RemoteContextLoadException._withCause(
        uri: uri,
        cause: 'Timeout: ${cause.message ?? "Request timed out"}',
      );
    }

    if (cause is FormatException) {
      return RemoteContextLoadException._withCause(
        uri: uri,
        cause: 'Invalid JSON response: ${cause.message}',
      );
    }

    return RemoteContextLoadException._withCause(
      uri: uri,
      cause: cause,
    );
  }

  RemoteContextLoadException._withCause({
    required Uri uri,
    required Object cause,
  }) : super(
          message: 'Failed to load remote context',
          failedUri: uri,
          cause: cause,
          operation: 'load_remote_context',
        );
}
