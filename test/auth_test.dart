/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'package:nock/nock.dart';
import 'package:test/test.dart';
import 'package:tiki_idp/auth/auth_model_rsp.dart';
import 'package:tiki_idp/auth/auth_repository.dart';

import 'fixtures/auth_nock.dart';

void main() {
  setUpAll(() => nock.init());
  setUp(() => nock.cleanAll());

  group('Auth Repository Tests', () {
    test('Grant - Success', () async {
      AuthNock nock = AuthNock();
      final Interceptor interceptor = nock.interceptor;

      AuthRepository repository = AuthRepository();
      AuthModelRsp jwt =
          await repository.grant(nock.clientId, 'storage registry');

      expect(interceptor.isDone, true);
      expect(jwt.accessToken, nock.accessToken);
      expect(jwt.refreshToken, nock.refreshToken);
      expect(jwt.scope?.length, 2);
      expect(jwt.scope?[0], 'storage');
      expect(jwt.tokenType, 'Bearer');
      expect(jwt.expires?.isAfter(DateTime.now()), true);
    });
  });
}
