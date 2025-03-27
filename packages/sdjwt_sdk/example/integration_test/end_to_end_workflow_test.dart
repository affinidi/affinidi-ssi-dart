import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:sdjwt_demo/main.dart';
import 'package:sdjwt_demo/widgets/home.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('SD-JWT Demo App Integration Tests', () {
    // Setup env
    Future<void> setupTestEnvironment(WidgetTester tester) async {
      //TODO: If you added more elements to the UI and made it longer, make sure to extend the size of the physical device as well.
      tester.view.physicalSize = const Size(1080, 2340);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);

      await tester.pumpWidget(const SdJwtDemoApp());
      await tester.pumpAndSettle();

      expect(find.text('Selective Disclosure JWT Demo'), findsOneWidget,
          reason: 'App title should be displayed');
      expect(find.byType(HomePage), findsOneWidget,
          reason: 'HomePage should be displayed');
    }

    void verifyHomeSections(WidgetTester tester) {
      expect(find.text('Key Settings'), findsOneWidget,
          reason: 'Key Settings section should exist');
      expect(find.text('Claims'), findsOneWidget,
          reason: 'Claims section should exist');
      expect(find.text('Selective Disclosures'), findsOneWidget,
          reason: 'Selective Disclosures section should exist');
      expect(find.text('Sample Cases'), findsOneWidget,
          reason: 'Sample Cases section should exist');
    }

    Future<void> navigateToResultsPage(WidgetTester tester) async {
      await tester.tap(find.byKey(const Key('continue_button')));
      await tester.pumpAndSettle();

      expect(find.text('SD-JWT Results'), findsOneWidget,
          reason: 'Results page title should be displayed');

      expect(find.byKey(const Key('sign_sd_jwt_button')), findsOneWidget,
          reason: 'Sign SD-JWT button should exist');
      expect(find.byKey(const Key('verify_sd_jwt_button')), findsOneWidget,
          reason: 'Verify SD-JWT button should exist');
      expect(find.byKey(const Key('reset_button')), findsOneWidget,
          reason: 'Reset button should exist');
    }

    Future<void> signSdJwt(WidgetTester tester,
        {required String keyType}) async {
      await tester.tap(find.byKey(const Key('sign_sd_jwt_button')));

      await tester.pump();
      await tester.pump(const Duration(seconds: 1));
      await tester.pumpAndSettle();

      expect(find.textContaining('Signed with $keyType'), findsOneWidget,
          reason: 'Should show signing confirmation with $keyType');
      expect(find.text('SD-JWT:'), findsOneWidget,
          reason: 'SD-JWT section should be displayed');
      expect(find.text('Decoded SD-JWT:'), findsOneWidget,
          reason: 'Decoded SD-JWT section should be displayed');

      expect(find.byKey(const Key('sd_jwt_text')), findsOneWidget,
          reason: 'SD-JWT text should be present');
      expect(find.byKey(const Key('decoded_sd_jwt_text')), findsOneWidget,
          reason: 'Decoded SD-JWT text should be present');
    }

    Future<void> verifySdJwt(WidgetTester tester) async {
      await tester.tap(find.byKey(const Key('verify_sd_jwt_button')));

      await tester.pump();
      await tester.pump(const Duration(seconds: 1));
      await tester.pumpAndSettle();

      expect(find.text('Verification Details:'), findsOneWidget,
          reason: 'Verification details section should be displayed');

      expect(find.textContaining('Verification: Success'), findsOneWidget,
          reason: 'Verification should succeed');

      expect(find.byKey(const Key('verification_details_text')), findsOneWidget,
          reason: 'Verification details text should be present');
    }

    Future<void> testReset(WidgetTester tester) async {
      await tester.tap(find.byKey(const Key('reset_button')));
      await tester.pumpAndSettle();

      expect(find.textContaining('Verification: Success'), findsNothing,
          reason: 'Verification result should be cleared after reset');
    }

    // Tests
    testWidgets('Complete SDJWT workflow test with the RSA',
        (WidgetTester tester) async {
      await setupTestEnvironment(tester);

      verifyHomeSections(tester);
      await navigateToResultsPage(tester);
      await signSdJwt(tester, keyType: 'RSA');
      await verifySdJwt(tester);
      await testReset(tester);
    });

    testWidgets('Complete SD-JWT workflow test with ECDSA',
        (WidgetTester tester) async {
      await setupTestEnvironment(tester);

      await tester.tap(find.text('ECDSA'));
      await tester.pumpAndSettle();

      verifyHomeSections(tester);
      await navigateToResultsPage(tester);
      await signSdJwt(tester, keyType: 'ECDSA');
      await verifySdJwt(tester);
      await testReset(tester);
    });

    testWidgets('sd functionality test', (WidgetTester tester) async {
      await setupTestEnvironment(tester);

      await tester.tap(find.text('Parse Claims'));
      await tester.pumpAndSettle();

      expect(find.byType(CheckboxListTile), findsWidgets,
          reason:
              'Disclosure checkboxes should be visible after parsing claims');

      final firstCheckbox = find.byType(CheckboxListTile).first;
      await tester.tap(firstCheckbox);
      await tester.pumpAndSettle();

      await navigateToResultsPage(tester);
      await signSdJwt(tester, keyType: 'RSA');
      await verifySdJwt(tester);

      final SelectableText verificationDetailsText =
          tester.widget<SelectableText>(
              find.byKey(const Key('verification_details_text')));

      expect(
        verificationDetailsText.data!.contains('claims'),
        isTrue,
        reason: 'Verification details should contain claims information',
      );
    });

    testWidgets('Error handling for the invalid keys',
        (WidgetTester tester) async {
      await setupTestEnvironment(tester);

      final privateKeyField = find.ancestor(
        of: find.text('Private Key'),
        matching: find.byType(TextField),
      );

      await tester.tap(find.descendant(
        of: privateKeyField,
        matching: find.byIcon(Icons.close),
      ));
      await tester.pumpAndSettle();
      await tester.enterText(privateKeyField, 'invalid-key-data');
      await tester.pumpAndSettle();

      await navigateToResultsPage(tester);

      await tester.tap(find.byKey(const Key('sign_sd_jwt_button')));
      await tester.pumpAndSettle();

      expect(find.byType(SnackBar), findsOneWidget,
          reason: 'Error SnackBar should be displayed for invalid key');
      expect(find.textContaining('failed'), findsOneWidget,
          reason: 'Error message should indicate failure');
    });
  });
}
