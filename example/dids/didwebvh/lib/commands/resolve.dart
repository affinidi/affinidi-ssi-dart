import 'dart:convert';
import 'dart:io';
import 'package:ssi/ssi.dart';

void resolveLocalFile(String path, {bool verify = false}) {
  final file = File(path);

  if (!file.existsSync()) {
    print('Error: File not found: $path');
    return;
  }

  try {
    final content = file.readAsStringSync();
    final log = DidWebVhLog.fromJsonLines(content);

    if (verify) {
      log.verify();
      print('Verification passed');
    }

    final lastEntry = log.entries.last;
    print('DID Document:');
    print(JsonEncoder.withIndent('  ').convert(lastEntry.state.toJson()));
  } on SsiException catch (e) {
    print('Verification failed');
    print('  Error: ${e.message}');
    print('  Code: ${e.code}');
    if (e.originalMessage != null) {
      print('  Details: ${e.originalMessage}');
    }
  } catch (e) {
    print('Error: $e');
  }
}
