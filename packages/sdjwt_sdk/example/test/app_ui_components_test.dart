import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sdjwt_demo/main.dart';
import 'package:sdjwt_demo/widgets/home.dart';

void main() {
  testWidgets('App render correctly with proper title',
      (WidgetTester tester) async {
    await tester.pumpWidget(const SdJwtDemoApp());

    expect(find.text('Selective Disclosure JWT Demo'), findsOneWidget);
    expect(find.byType(MaterialApp), findsOneWidget);
    expect(find.byType(HomePage), findsOneWidget);
  });

  testWidgets('Home page contains all required sections',
      (WidgetTester tester) async {
    await tester.pumpWidget(const SdJwtDemoApp());

    expect(find.text('Key Settings'), findsOneWidget);
    expect(find.text('Claims'), findsOneWidget);
    expect(find.text('Selective Disclosures'), findsOneWidget);
    expect(find.text('Sample Cases'), findsOneWidget);
    expect(find.text('RSA'), findsOneWidget);
    expect(find.text('ECDSA'), findsOneWidget);
    expect(find.byKey(const Key('continue_button')), findsOneWidget);
  });

  testWidgets('Can scroll and finding continue button',
      (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1080, 2340);
    tester.view.devicePixelRatio = 1.0;

    await tester.pumpWidget(const SdJwtDemoApp());
    await tester.scrollUntilVisible(
      find.byKey(const Key('continue_button')),
      500.0,
      scrollable: find.byType(Scrollable).first,
    );

    expect(find.byKey(const Key('continue_button')), findsOneWidget);
  });

  testWidgets('Can navigate to the results page', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1080, 2340);
    tester.view.devicePixelRatio = 1.0;

    await tester.pumpWidget(const SdJwtDemoApp());
    await tester.scrollUntilVisible(
      find.byKey(const Key('continue_button')),
      500.0,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.tap(find.byKey(const Key('continue_button')));
    await tester.pumpAndSettle();

    expect(find.text('SD-JWT Results'), findsOneWidget);
    expect(find.byKey(const Key('sign_sd_jwt_button')), findsOneWidget);
    expect(find.byKey(const Key('verify_sd_jwt_button')), findsOneWidget);
    expect(find.byKey(const Key('reset_button')), findsOneWidget);
  });
}
