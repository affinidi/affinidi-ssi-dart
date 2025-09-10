import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:test/test.dart';

void main() {
  group('JsonLdContext', () {
    test('fromJson with a single URI string', () {
      final ctx = JsonLdContext.fromJson('https://example.org/context');
      expect(ctx.uris, hasLength(1));
      expect(ctx.uris.first.toString(), equals('https://example.org/context'));
      expect(ctx.terms, isEmpty);
      final json = ctx.toJson();
      expect(json, isA<List>());
      expect(json, equals(['https://example.org/context']));
    });

    test('fromJson with terms map only', () {
      final input = {
        '@vocab': 'https://schema.org/',
        'name': 'schema:name',
      };
      final ctx = JsonLdContext.fromJson(input);
      expect(ctx.uris, isEmpty);
      expect(ctx.terms, hasLength(2));
      expect(ctx['@vocab'], equals('https://schema.org/'));
      expect(ctx['name'], equals('schema:name'));

      final json = ctx.toJson();
      expect(json, isA<Map>());
      expect((json as Map)['@vocab'], equals('https://schema.org/'));
    });

    test('fromJson with mixed list of uris and term objects', () {
      final input = [
        'https://www.w3.org/ns/credentials/v2',
        {'@vocab': 'https://schema.org/'},
        'https://example.org/extra',
        {'name': 'schema:name'}
      ];

      final ctx = JsonLdContext.fromJson(input);

      expect(ctx.uris, hasLength(2));
      expect(
          ctx.uris.map((u) => u.toString()).toList(),
          containsAll([
            'https://www.w3.org/ns/credentials/v2',
            'https://example.org/extra'
          ]));

      expect(ctx.terms, hasLength(2));
      expect(ctx['@vocab'], equals('https://schema.org/'));
      expect(ctx['name'], equals('schema:name'));

      final json = ctx.toJson();
      expect(json, isA<List>());
      final listJson = json as List;
      expect(listJson.last, isA<Map>());
      expect((listJson.last as Map)['@vocab'], equals('https://schema.org/'));
      expect(
          listJson.sublist(0, 2),
          equals([
            'https://www.w3.org/ns/credentials/v2',
            'https://example.org/extra',
          ]));
    });

    test('null input yields empty context and toJson returns {}', () {
      final ctx = JsonLdContext.fromJson(null);
      expect(ctx.uris, isEmpty);
      expect(ctx.terms, isEmpty);
      expect(ctx.toJson(), equals({}));
    });

    test('JsonLdContext is immutable (unmodifiable views)', () {
      final ctx = JsonLdContext.fromJson({
        '@vocab': 'https://schema.org/',
      });

      expect(ctx.uris, isA<Iterable>());
      expect(() => (ctx.uris as dynamic).add(Uri.parse('https://a')),
          throwsUnsupportedError);

      expect(ctx.terms, isA<Map>());
      expect(
          () => (ctx.terms as dynamic)['foo'] = 'bar', throwsUnsupportedError);
    });

    test('unsupported context type throws SsiException', () {
      expect(
        () => JsonLdContext.fromJson(123),
        throwsA(predicate((e) {
          if (e is SsiException) {
            final msg = e.message.toString();
            return msg.contains('Unsupported @context type') &&
                msg.contains('int');
          }
          return false;
        })),
      );
    });
  });

  group('MutableJsonLdContext', () {
    test('fromJson with terms and mutability', () {
      final ctx = MutableJsonLdContext.fromJson({
        '@vocab': 'https://schema.org/',
        'name': 'schema:name',
      });

      expect(ctx.uris, isEmpty);
      expect(ctx.terms, hasLength(2));
      expect(ctx['name'], equals('schema:name'));

      ctx.terms['age'] = 'schema:age';
      expect(ctx['age'], equals('schema:age'));
      expect(ctx.keys, containsAll(['@vocab', 'name', 'age']));

      final json = ctx.toJson();
      expect(json, isA<Map>());
      expect((json as Map)['age'], equals('schema:age'));
    });

    test('mutating uris reflected in toJson when terms also exist', () {
      final ctx =
          MutableJsonLdContext.fromJson(['https://example.org/context']);

      ctx.terms['foo'] = 'bar';
      ctx.uris.add(Uri.parse('https://extra.org/c'));

      final json = ctx.toJson();
      expect(json, isA<List>());

      final listJson = json as List;
      expect(
          listJson.sublist(0, 2),
          equals([
            'https://example.org/context',
            'https://extra.org/c',
          ]));
      expect(listJson.last, isA<Map>());
      expect((listJson.last as Map)['foo'], equals('bar'));
    });
  });
}
