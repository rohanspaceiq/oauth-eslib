angular.module('oauth')
  .factory('oauthIOffice', ['OAuth', 'oaHost', '$http', '$location', oaIOffice]);


/**
 * The `OAuth` service provides functions to provide information about
 * the user who is logged in and to make rest api calls.
 */
function oaIOffice(OAuth, oaHost, $http, $location) {

  var config = {
    token: '/external/api/oauth2/token',
    revoke: '/external/api/oauth2/revoke',
    tokenInfo: '/external/api/oauth2/tokeninfo'
  };
  return {
    requestToken: requestToken,
    refreshToken: refreshToken,
    verifyToken: verifyToken,
    logout: logout,
    onAccessDenied: onAccessDenied,
    getAccessHeaders: getAccessHeaders,
    badCredentials: badCredentials
  };


  /**
   * Exchanges an authorization code by an access token.
   */
  function requestToken(code) {
    oaHost.loadHost();
    return $http({
      method: "post",
      url: oaHost.composeAPIPath(config.token),
      headers: {
        'Content-type': 'application/json',
        'x-grant-type': 'authorization_code',
        'x-redirect-uri': oaHost.redirectUri,
        'x-client-id': oaHost.clientId,
        'x-scope': oaHost.scope,
        'x-auth-code': code
      }
    }).then(
      function(response) {
        return OAuth.accessAllowed(response.data);
      },
      function(response) {
        if (!response.data) { return OAuth.accessUnavailable('requestToken'); }
        var dat = response.data,
          reason = dat.error + ': ' + dat.errorDescription;
        return OAuth.accessDenied(reason);
      }
    );
  }


  /**
   * Attempts to obtain and set a new token via the refresh token.
   * You may catch the event `oauth:refreshTokenError` to handle
   * the event when we cannot retrieve a new access token. The event
   * comes along with an object with properties `status`, `error` and
   * `errorDescription`.
   */
  function refreshToken(token) {
    oaHost.loadHost();
    return $http({
      method: "post",
      url: oaHost.composeAPIPath(config.token),
      headers: {
        'Content-type': 'application/json',
        'x-grant-type': 'refresh_token',
        'x-redirect-uri': oaHost.redirectUri,
        'x-client-id': oaHost.clientId,
        'x-scope': oaHost.scope,
        'x-refresh-token': token
      }
    }).then(
      function(response) {
        return OAuth.accessAllowed(response.data);
      },
      function(response) {
        if (!response.data) { return OAuth.accessUnavailable('refreshToken'); }
        var dat = response.data,
          reason = dat.error + ': ' + dat.errorDescription;
        return OAuth.accessDenied(reason);
      }
    );
  }


  /**
   * Return a promise to inform us if the token is valid. The
   * promise will return an object with the attributes `status`
   * and `reason`. A true status means that the token is valid.
   * When the token is invalid the `reason` property will be set.
   */
  function verifyToken(accessToken) {
    return $http({
      method: "get",
      url: oaHost.composeAPIPath(config.tokenInfo),
      headers: {
        'x-token': accessToken
      }
    }).then(
      function() {
        return OAuth.accessAllowed();
      },
      function(response) {
        if (!response.data) { return OAuth.accessUnavailable('verifyToken'); }
        var dat = response.data,
          reason = dat.error + ': ' + dat.errorDescription;
        return OAuth.accessDenied(reason);
      }
    );
  }


  /**
   * Removes the token and informs the server that the token is no
   * longer needed.
   */
  function logout(accessToken) {
    return $http({
      method: "get",
      url: oaHost.composeAPIPath(config.revoke),
      headers: {
        'x-token': accessToken
      }
    });
  }


  /**
   * Send user to the app root. This function is invasive but it is
   * being presented here to point out that if the module defines
   * this function then the OAuth service will call the function when
   * the access is denied. To change the behaviour make sure to
   * overwrite this function, i.e. oaIOffice.onAccessDenied = null;
   *
   * You may expect to have two inputs: reason and location. Location
   * may not always be set.
   */
  function onAccessDenied() {
    console.log('ioffice.js onAccessDenied');
    $location.path('/');
  }


  /**
   * Get an object with the iOffice access headers.
   *
   * @returns {Object} The authorization headers
   */
  function getAccessHeaders() {
    if ('oauth-dev' in window.localStorage) {
      var data = window.localStorage['oauth-dev'].split(',');
      var user = data[2], pass = data[3];
      return {
        'x-auth-username': user,
        'x-auth-password': pass
      };
    }
    return {
      'x-access-token': OAuth.getAccessToken()
    };
  }


  /**
   * Return true if the error response was due to bad credentials.
   *
   * The contents of the method are already implemented in
   * the OAuth service. We may remove this function from the iOffice
   * module and it will behave correctly. This is written here to
   * show how to overwrite the default. This is not done in the
   * iOffice module but we can do a similar function called:
   * "mayRefresh" which checks if the error response allows us to
   * refresh the token (by default it checks if the status was 403).
   *
   * @returns {Boolean} True if error due to bad credentials.
   */
  function badCredentials(response) {
    return (response.status == 401);
  }

}
