/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

class AuthModelRsp {
  String? accessToken;
  String? refreshToken;
  List<String>? scope;
  String? tokenType;
  DateTime? expires;

  AuthModelRsp(
      {this.accessToken,
      this.refreshToken,
      this.scope,
      this.tokenType,
      this.expires});

  AuthModelRsp.fromMap(Map<String, dynamic>? map) {
    if (map != null) {
      accessToken = map['access_token'];
      refreshToken = map['refresh_token'];
      tokenType = map['token_type'];
      scope = (map['scope'] as String?)?.split(' ');
      expires = DateTime.now().add(Duration(seconds: map['expires_in'] ?? 0));
    }
  }

  @override
  String toString() {
    return 'AuthModelRsp{accessToken: $accessToken, refreshToken: $refreshToken, scope: $scope, tokenType: $tokenType, expires: $expires}';
  }
}
