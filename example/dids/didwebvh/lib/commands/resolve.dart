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

void resolveRemoteDid(String did, {bool urlOnly = false}) {
  final didUrl = DidWebVhUrl.fromDid(did);

  if (urlOnly) {
    print('Log: ${didUrl.toJsonLogFileUrl()}');
    print('Doc: ${didUrl.toJsonLogFileUrl().replaceAll('.jsonl', '.json')}');
  } else {
    print('Remote resolve not implemented yet');
    print('SCID: ${didUrl.scid}');
  }
}
