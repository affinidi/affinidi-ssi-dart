import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';

/// Utility for validating Data Integrity related @context entries
/// for both RDF Dataset Canonicalization (RDFC) and JCS cryptosuites.
///
/// Rules:
/// - Accept if credential v2 context present (https://www.w3.org/ns/credentials/v2).
/// - Otherwise require explicit data-integrity context v2 or v1.
/// - Throw invalidContext if @context missing or not a string/array of strings.
///
/// Returns the normalized list of context URLs.
class DataIntegrityContextUtil {
  DataIntegrityContextUtil._();

  static const vcV2Context = 'https://www.w3.org/ns/credentials/v2';
  static const dataIntegrityV2 = 'https://w3id.org/security/data-integrity/v2';
  static const dataIntegrityV1 = 'https://w3id.org/security/data-integrity/v1';

  static List<String> validate(Map<String, dynamic> document) {
    final ctxDynamic = document['@context'];
    if (ctxDynamic == null) {
      throw SsiException(
        message: 'Missing @context in document for Data Integrity issuance',
        code: SsiExceptionType.invalidContext.code,
      );
    }

    List<String> ctxList;
    if (ctxDynamic is String) {
      ctxList = [ctxDynamic];
    } else if (ctxDynamic is List) {
      ctxList = ctxDynamic.whereType<String>().toList();
    } else {
      throw SsiException(
        message: 'Unsupported @context structure for Data Integrity issuance',
        code: SsiExceptionType.invalidContext.code,
      );
    }

    final hasVcV2 = ctxList.contains(vcV2Context);
    final hasDataIntegrity =
        ctxList.contains(dataIntegrityV2) || ctxList.contains(dataIntegrityV1);

    if (!hasVcV2 && !hasDataIntegrity) {
      throw SsiException(
        message:
            'Document @context missing Data Integrity definitions. Add $dataIntegrityV2 or use credentials v2 context.',
        code: SsiExceptionType.invalidContext.code,
      );
    }
    return ctxList;
  }
}
