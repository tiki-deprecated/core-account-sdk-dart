/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'JWT.dart';
import 'auth_model_rsp.dart';
import 'auth_repository.dart';

class AuthService {
  final String _clientId;
  final String? _clientSecret;
  final String _scope;
  final AuthRepository _repository;

  JWT? cached;

  AuthService(this._clientId, List<String> scope, {String? clientSecret})
      : _scope = scope.join(" "),
        _clientSecret = clientSecret,
        _repository = AuthRepository();

  Future<JWT> grant() async {
    AuthModelRsp rsp =
        await _repository.grant(_clientId, _scope, clientSecret: _clientSecret);
    cached = JWT(rsp.accessToken!, rsp.tokenType!, rsp.expires!,
        refreshToken: rsp.refreshToken, scope: rsp.scope);
    return cached!;
  }

  Future<JWT> get token async {
    DateTime cutoff = DateTime.now().add(const Duration(minutes: 2));
    if (cached == null ||
        cached?.expires == null ||
        cached!.expires.isBefore(cutoff)) {
      return grant();
    }
    return Future.value(cached);
  }
}
