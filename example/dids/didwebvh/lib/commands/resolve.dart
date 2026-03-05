import 'dart:convert';
import 'dart:io';
import 'package:ssi/ssi.dart';

Future<void> resolveDid(String didString, {bool verify = true}) async {
  try {
    final didWebVh = DidWebVhUrl.fromUrlString(didString);
    final (doc, docMetadata, _) = await didWebVh.resolveDidWithMetadata(
      options: verify
          ? null
          : DidWebVhResolutionOptions(
              skipHashEntryVerification: true,
              skipProofVerification: true,
              skipKeyPreRotationVerification: true,
              skipWitnessVerification: true,
              skipScidVerification: true,
            ),
    );
    if (!verify) {
      print('Verification skipped');
    } else {
      print('Verification passed');
    }
    printDidDocument(doc);
    printJson('Document Metadata',
        (docMetadata as DidWebVhDocumentMetadata).toJson());
  } on SsiException catch (e) {
    print('Resolution failed');
    printSsiException(e);
  } catch (e) {
    print('Error: $e');
  }
}

// Resolve a local .jsonl file containing DID webvh log entries.
// We use low  level API' here to demonstrate verify and loading from file.
Future<void> resolveLocalFile(String path, {bool verify = true}) async {
  final file = File(path);

  if (!file.existsSync()) {
    print('Error: File not found: $path');
    return;
  }

  try {
    final content = file.readAsStringSync();
    final log = DidWebVhLog.fromJsonLines(content);

    await log.verify(
        options:
            verify ? DidWebVhResolutionOptions() : _skipVerificationOptions);
    if (!verify) {
      print('Verification skipped');
    } else {
      print('Verification passed');
    }

    final lastEntry = log.entries.last;
    printDidDocument(lastEntry.state);
  } on SsiException catch (e) {
    print('Verification failed');
    printSsiException(e);
  } catch (e) {
    print('Error: $e');
  }
}

final _skipVerificationOptions = DidWebVhResolutionOptions(
  skipHashEntryVerification: true,
  skipProofVerification: true,
  skipKeyPreRotationVerification: true,
  skipWitnessVerification: true,
  skipScidVerification: true,
);

void printJson(String label, Map<String, dynamic> json) {
  print('$label:');
  print(JsonEncoder.withIndent('  ').convert(json));
}

void printDidDocument(DidDocument doc) {
  printJson('DID Document', doc.toJson());
}

void printSsiException(SsiException e) {
  print('  Error: ${e.message}');
  print('  Code: ${e.code}');
  if (e.originalMessage != null) {
    print('  Details: ${e.originalMessage}');
  }
}
