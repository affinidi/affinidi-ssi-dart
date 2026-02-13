import 'dart:io';
import 'package:ssi/ssi.dart';

void resolveLocalFile(String path) {
  final file = File(path);

  if (!file.existsSync()) {
    print('Error: File not found: $path');
    return;
  }

  try {
    final content = file.readAsStringSync();
    final log = DidWebVhLog.fromJsonLines(content);
    print('Loaded ${log.entries.length} entries from $path');

    log.verify();
    print('Verification: ✓ passed');
  } catch (e) {
    print('Verification: ✗ failed');
    print('  $e');
  }
}
