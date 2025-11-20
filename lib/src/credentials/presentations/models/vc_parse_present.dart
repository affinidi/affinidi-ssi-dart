import 'dart:convert';

import '../../credentials.dart';

const String _dataIntegrityProofContext =
    'https://w3id.org/security/data-integrity/v2';

/// Parses a [ParsedVerifiableCredential] from JSON or string input.
///
/// Accepts either a raw credential object or its serialized string form.
/// Delegates to [UniversalParser].
ParsedVerifiableCredential parseVC(dynamic e) {
  String encoded;
  if (e is! String) {
    encoded = jsonEncode(e);
  } else {
    encoded = e;
  }

  return UniversalParser.parse(encoded);
}

/// Converts a [ParsedVerifiableCredential] into its presentable form
/// using the appropriate VC suite.
///
/// When embedding VCs with DataIntegrityProof in presentations that use
/// different proof types (e.g., secp256k1 VP containing Ed25519 VC),
/// this ensures each DataIntegrityProof includes its required @context
/// for proper JSON-LD processing.
dynamic presentVC(ParsedVerifiableCredential credential) {
  final suite = VcSuites.getVcSuite(credential);
  final present = suite.present(credential);

  if (present is! String && present is! Map<String, dynamic>) {
    final vcJson = credential.toJson();
    if (_hasDataIntegrityProof(vcJson)) {
      return _ensureProofContext(vcJson);
    }
    return vcJson;
  }

  if (present is Map<String, dynamic>) {
    if (_hasDataIntegrityProof(present)) {
      return _ensureProofContext(present);
    }
    return present;
  }

  return present;
}

/// Checks if a VC has DataIntegrityProof
bool _hasDataIntegrityProof(Map<String, dynamic> vcJson) {
  final proof = vcJson['proof'];

  if (proof == null) return false;

  if (proof is Map<String, dynamic>) {
    return proof['type'] == 'DataIntegrityProof';
  }

  if (proof is List) {
    return proof.any(
        (p) => p is Map<String, dynamic> && p['type'] == 'DataIntegrityProof');
  }

  return false;
}

/// Ensures DataIntegrityProof proofs have @context when embedded in VPs.
Map<String, dynamic> _ensureProofContext(Map<String, dynamic> vcJson) {
  final proof = vcJson['proof'];

  if (proof == null) return vcJson;

  // Handle single proof
  if (proof is Map<String, dynamic>) {
    if (proof['type'] == 'DataIntegrityProof' &&
        !proof.containsKey('@context')) {
      vcJson = Map<String, dynamic>.from(vcJson);
      vcJson['proof'] = {
        '@context': _dataIntegrityProofContext,
        ...proof,
      };
    }
  }
  // Handle array of proofs
  else if (proof is List) {
    final updatedProofs = <dynamic>[];
    var needsUpdate = false;

    for (final p in proof) {
      if (p is Map<String, dynamic>) {
        if (p['type'] == 'DataIntegrityProof' && !p.containsKey('@context')) {
          updatedProofs.add({
            '@context': _dataIntegrityProofContext,
            ...p,
          });
          needsUpdate = true;
        } else {
          updatedProofs.add(p);
        }
      } else {
        updatedProofs.add(p);
      }
    }

    if (needsUpdate) {
      vcJson = Map<String, dynamic>.from(vcJson);
      vcJson['proof'] = updatedProofs;
    }
  }

  return vcJson;
}
