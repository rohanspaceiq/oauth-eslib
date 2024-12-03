angular.module('oauth')
    .factory('oaHost', ['oaHash', 'oaLog', oaHost]);

/**
 * Service to set and access the information of the host providing the
 * access tokens.
 */
function oaHost(oaHash, oaLog) {

  var host = null;
  var required = [
    'host',
    'site',
    'clientId',
    'redirectUri',
    'authorizePath'
  ];
  var optional = {
    'clientSecret': '',
    'scope': '',
    'state': ''
  };
  var service = {
    name: '',
    site: '',
    clientId: '',
    redirectUri: '',
    authorizedPath: '',
    clientSecret: '',
    scope: '',
    state: '',

    loadHost: loadHost,
    storeHost: storeHost,
    clearHost: clearHost,
    composeAuthPath: composeAuthPath,
    composeAPIPath: composeAPIPath

    //Exposed only for testing purposes
    //,createHost: createHost
  };
  return service;


  /**
   * Retrieves the host object. If no host is set then it attempts
   * to set it. Returns null if no host is found.
   *
   * @returns {Object} The host object.
   */
  function loadHost() {
    return host || storeHost();
  }


  /**
   * Sets and returns the host object. It tries the following:
   * - takes the host from the function parameter (if given)
   * - takes the host from the local storage.
   *
   * @param {Object} [hostObj] The host object to store.
   * @returns {Object} The host object.
   */
  function storeHost(hostObj) {
    var obj = null,
        inStorage = false;
    if (hostObj) {
      obj = createHost(hostObj);
    } else if ('oauth-host' in window.localStorage) {
      obj = createHost(JSON.parse(window.localStorage['oauth-host']));
      if (obj) {
        inStorage = true;
      }
    }
    host = obj;
    if (host) {
      if (!inStorage) {
        oaLog.debug('oaHost::storeHost', 'Storing ' + host.host + ' host');
        window.localStorage['oauth-host'] = JSON.stringify(host);
      }
      service.name = host.host;
      service.site = host.site;
      service.clientId = host.clientId;
      service.redirectUri = host.redirectUri;
      service.authorizedPath = host.authorizedPath;
      service.clientSecret = host.clientSecret;
      service.scope = host.scope;
      service.state = host.state;
    } else {
      clearHost();
    }
    return host;
  }


	/**
	 * Removes the host from storage.
	 */
	function clearHost() {
    service.name = '';
    service.site = '';
    service.clientId = '';
    service.redirectUri = '';
    service.authorizedPath = '';
    service.clientSecret = '';
    service.scope = '';
    service.state = '';
		delete window.localStorage['oauth-host'];
		host = null;
	}


  /**
   * Composes the url where the user authorization takes place. The
   * default query parameters may be overwritten by passing the input
   * parameter. By default the authorization path will have the
   * following query parameters:
   *
   *  - client_id
   *  - redirect_uri
   *  - scope
   *  - response_type
   *  - state
   *
   * Each of their values depends on how the host was configured, with
   * the exception of "response_type" which defaults to 'code'.
   *
   * @returns {String} The authorization url.
   */
  function composeAuthPath(params) {
    var queryParams = {
      client_id: host.clientId,
      redirect_uri: host.redirectUri,
      scope: host.scope,
      response_type: 'code',
      state: host.state
    };
    angular.extend(queryParams, params);
    return composeAPIPath(host.authorizePath, queryParams);
  }


  /**
   * Composes a url with the `site`s host object property as its base
   * path. Returns null if the host has not been set.
   *
   * @returns {String} The composed path.
   */
  function composeAPIPath(endpoint, params) {
    if (host) {
      params = params || {};
      var authPathHasQuery = (host.authorizePath.indexOf('?') != -1),
          appendChar = (authPathHasQuery) ? '&' : '?',
          queryParams = oaHash.compose(params),
          path = host.site + endpoint;
      if (queryParams) {
        path += appendChar + queryParams;
      }
      return path;
    }
    return null;
  }


  /**
   * Creates a new object with all the required fields for a valid
   * host. Some fields are optional and will default to an empty
   * string in the case they are not provided. If the required fields
   * are not present the function will return null.
   *
   * Required fields:
   * - host
   * - site
   * - clientId
   * - redirectUri
   * - authorizePath
   *
   * Optional:
   * - clientSecret
   * - scope
   * - state
   *
   * @param {Object} params Object with the token parameters.
   * @returns {Object} The host object
   */
  function createHost(params) {
    if (!hasAttributes(params, required)) {
      return null;
    }
    return _.defaults(params, optional);
  }

}
