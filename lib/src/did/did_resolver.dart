import 'dart:convert';

import 'package:http/http.dart' as http;

import 'did_document.dart';
import 'did_key.dart';
import 'did_peer.dart';
import 'did_web.dart';

/// Resolves the Did-Document for [did].
///
/// Resolving if did:key can be done internally, for all other did-methods an URL [resolverAddress] to an instance of a universal resolver is needed.
// FIXME add tests
Future<DidDocument> resolveDidDocument(
  String did, {
  String? resolverAddress,
}) async {
  if (did.startsWith('did:key')) {
    return DidKey.resolve(did);
  } else if (did.startsWith('did:peer')) {
    return DidPeer.resolve(did);
  } else if (did.startsWith('did:web')) {
    return DidWeb.resolve(did);
  } else {
    if (resolverAddress == null) {
      throw Exception(
          'The did con only be resolved using universal resolver, therefore the resolver address is required');
    }
    try {
      var res = await http
          .get(Uri.parse('$resolverAddress/1.0/identifiers/$did'))
          .timeout(Duration(seconds: 30));
      if (res.statusCode == 200) {
        var didResolution = jsonDecode(res.body);
        return DidDocument.fromJson(didResolution['didDocument']);
      } else {
        throw Exception('Bad status code ${res.statusCode}');
      }
    } catch (e) {
      throw Exception('Something went wrong during resolving: $e');
    }
  }
}
