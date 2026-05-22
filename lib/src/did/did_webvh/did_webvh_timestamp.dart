/// Formats and parses did:webvh timestamps as whole-second UTC values.
class DidWebVhTimestamp {
  final _pattern = RegExp(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$',
  );

  /// Formats a [DateTime] as a did:webvh timestamp string.
  /// It does not include fractional seconds and always uses UTC timezone.
  String format(DateTime value) {
    final utcValue = value.toUtc();
    final year = utcValue.year.toString().padLeft(4, '0');
    final month = utcValue.month.toString().padLeft(2, '0');
    final day = utcValue.day.toString().padLeft(2, '0');
    final hour = utcValue.hour.toString().padLeft(2, '0');
    final minute = utcValue.minute.toString().padLeft(2, '0');
    final second = utcValue.second.toString().padLeft(2, '0');
    return '$year-$month-${day}T$hour:$minute:${second}Z';
  }

  /// Parses a did:webvh timestamp string into a [DateTime] object.
  /// The input must be in the format produced by [format], and the resulting
  /// DateTime will be in UTC.
  /// Throws a [FormatException] if the input is not a valid did:webvh timestamp.
  /// The parser is strict and will reject values that do not exactly match the format,
  /// including those with fractional seconds or incorrect timezone indicators.
  DateTime parse(String value) {
    final match = _pattern.firstMatch(value);
    if (match == null) {
      throw FormatException('Invalid did:webvh timestamp format', value);
    }

    final year = int.parse(match.group(1)!);
    final month = int.parse(match.group(2)!);
    final day = int.parse(match.group(3)!);
    final hour = int.parse(match.group(4)!);
    final minute = int.parse(match.group(5)!);
    final second = int.parse(match.group(6)!);

    final parsed = DateTime.utc(year, month, day, hour, minute, second);
    if (format(parsed) != value) {
      throw FormatException('Invalid did:webvh timestamp value', value);
    }

    return parsed;
  }
}
