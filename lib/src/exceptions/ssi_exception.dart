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
}
