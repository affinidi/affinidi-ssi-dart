class SsiException implements Exception {
  SsiException({
    required this.message,
    required this.code,
    this.originalMessage,
  });

  final String message;
  final String code;
  final String? originalMessage;
}
