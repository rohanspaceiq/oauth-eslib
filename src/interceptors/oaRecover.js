angular.module('oauth')
    .factory('oaRecovery', ['$q', '$injector', OAuthRecovery])
    .config(['$httpProvider', function($httpProvider) {
      $httpProvider.interceptors.push('oaRecovery');
    }]);


/**
 * Intercepts http error responses and checks if the errors are due
 * to bad credentials or insufficient permissions (may refresh). It
 * handles the responses according the host.
 *
 */
function OAuthRecovery($q, $injector) {
  return {
    responseError: responseError
  };

  function responseError(response) {
    var $http = $injector.get('$http'),
        OAuth = $injector.get('OAuth'),
        oaLog = $injector.get('oaLog'),
        deferred = $q.defer(),
        reason;

    if (OAuth.badCredentials(response)) {

      oaLog.debug('OAuth::Recovery', 'Request failed due to bad credentials...');
      reason = "access_denied: The server does not recognize the credentials.";
      console.log('oaRecover if (OAuth.badCredentials', reason);
      OAuth.onAccessDenied(reason);
      response.status = 0;
      return $q.reject(response);

    } else if (OAuth.mayRefresh(response)) {

      if (OAuth.getRefreshToken()) {

        oaLog.debug('OAuth::Recovery', 'Request failed but we may be able to recover...');
        OAuth.refreshToken().then(deferred.resolve, deferred.reject);
        return deferred.promise.then(function() {
          OAuth.setAccessHeaders(response.config.headers);
          return $http(response.config);
        });

      } else {

        oaLog.debug('OAuth::Recovery', 'Request failed while using the implicit grant, cannot recover...');
        reason = "access_denied: Cannot obtain automatic access while using the implicit grant.";
        console.log('oaRecover if (OAuth.getRefreshToken())', reason);
        OAuth.onAccessDenied(reason);
        return $q.reject(response);

      }

    }
    return $q.reject(response);
  }
}
