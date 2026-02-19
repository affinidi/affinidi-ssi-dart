import 'dart:io';
import 'package:args/args.dart';
import 'package:didwebvh/commands/resolve.dart';

Future<void> main(List<String> arguments) async {
  final parser = ArgParser();

  final resolveParser = ArgParser()
    ..addFlag('no-verify', help: 'Skip verification checks');

  parser.addCommand('resolve', resolveParser);
  parser.addFlag('help', abbr: 'h', help: 'Show help');

  final results = parser.parse(arguments);

  if (results['help'] as bool || results.command == null) {
    print('Usage: didwebvh resolve <did|file> [--url-only]');
    return;
  }

  if (results.command!.name == 'resolve') {
    final args = results.command!;

    if (args.rest.isEmpty) {
      print('Error: resolve requires a DID or file argument');
      return;
    }

    final input = args.rest[0];
    final verify = !(args['no-verify'] as bool);
    final isFile = input.endsWith('.jsonl') || File(input).existsSync();

    if (isFile) {
      resolveLocalFile(input, verify: verify);
    } else if (input.startsWith('did:webvh:')) {
      await resolveDid(input, verify: verify);
    } else {
      print('Error: must be a .jsonl file or did:webvh:... DID');
    }
  }
}
