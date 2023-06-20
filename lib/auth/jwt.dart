/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

class JWT {
  final String accessToken;
  final String tokenType;
  final DateTime expires;
  final String? refreshToken;
  final List<String>? scope;

  JWT(this.accessToken, this.tokenType, this.expires,
      {this.refreshToken, this.scope});

  @override
  String toString() {
    return 'JWT{accessToken: $accessToken, tokenType: $tokenType, expires: $expires, refreshToken: $refreshToken, scope: $scope}';
  }
}
