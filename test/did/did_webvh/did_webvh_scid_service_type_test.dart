import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('SCID verification over the published log entry', () {
    final didWebVhUrl = DidWebVhUrl.fromUrlString(
        'did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com');

    test('verifies an entry whose service type is a single-element array',
        () async {
      const jsonLines =
          r'{"versionId":"1-QmNjd1quEJC6Mfq37yn7V1k9U5ykUzigFca1zwukNryqzW","versionTime":"2026-06-13T17:12:20Z","parameters":{"method":"did:webvh:1.0","scid":"QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj","updateKeys":["z6MktxYNded4t8Ff5EpGM4sNYJHn5sfA27hdzJgdkcJ2ToQY"],"portable":true,"nextKeyHashes":["z6MkvNCJm9feeCxRK4oCt461PNQkvc1bt7JpfmtNx7gUv9kj"]},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1","https://didcomm.org/messaging/v2"],"assertionMethod":["did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com#key-0"],"authentication":["did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com#key-0"],"id":"did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com","keyAgreement":["did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com#key-1"],"service":[{"id":"did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com#service","serviceEndpoint":[{"accept":["didcomm/v2"],"routingKeys":[],"uri":"https://mediator.example.com/mediator/v1"},{"accept":["didcomm/v2"],"routingKeys":[],"uri":"wss://mediator.example.com/mediator/v1/ws"}],"type":["DIDCommMessaging"]},{"id":"did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com#auth","serviceEndpoint":"https://mediator.example.com/mediator/v1/authenticate","type":["Authentication"]}],"verificationMethod":[{"controller":"did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com","id":"did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com#key-0","publicKeyMultibase":"z6MkoL8qQrVju4uGyCWGfU2HH8iBYE9Nc8MbZbK4pgSrMETL","type":"Multikey"},{"controller":"did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com","id":"did:webvh:QmY29n4pk1Ge8suzgqhqEwR38no6m9zTrcpuXjn6rXmfQj:mediator.example.com#key-1","publicKeyMultibase":"z6LSd9YCdimAYMotGmeakbnHrqV3GxhBuzzt1GdVis3zKgvm","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-06-13T17:12:20Z","verificationMethod":"did:key:z6MktxYNded4t8Ff5EpGM4sNYJHn5sfA27hdzJgdkcJ2ToQY#z6MktxYNded4t8Ff5EpGM4sNYJHn5sfA27hdzJgdkcJ2ToQY","proofPurpose":"assertionMethod","proofValue":"z3V4DPrHD3wmijMGJen6BN6EGb1nw5VJereUYrBvJBfT6QpSvCJ1oSNbrXCyGn6bfCk9CcCqhyUMHNaKnaFEYw5c4"}]}';

      final log = DidWebVhLog.fromJsonLines(jsonLines);

      await expectLater(
        log.verify(
          options: DidWebVhResolutionOptions(
            resolvingDidUrl: didWebVhUrl,
            skipResolvedDidDocScidVerification: true,
            skipWitnessVerification: true,
          ),
        ),
        completes,
      );
    });
  });
}
