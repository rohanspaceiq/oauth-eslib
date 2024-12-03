angular.module('oauth')
    .factory('oaToken', ['oaHash', 'oaLog', oaToken]);


/**
 * The `oaToken` service provides functions to storeToken and access an oauth
 * token. Note that there is only one token per session. This token
 * may be stored indefinitely in the local storage.
 */
function oaToken(oaHash, oaLog) {

  var token = null;
  var required = [
    'token_type', 'access_token', 'expires_in'
  ];
  var optional = {
    'expires_at': null,
    'refresh_token': '',
    'scope': '',
    'state': ''
  };
  var service = {
    accessToken: '',
    refreshToken: '',

    loadToken: loadToken,
    storeToken: storeToken,
    clearToken: clearToken,
    isExpired: isExpired

    //Exposed only for testing purposes.
    //,createToken: createToken,
    //extractHash: extractHash
  };
  return service;

  /**
   * Retrieve the underlying token object. This object contains the
   * following keys:
   *
   *  token_type
   *  access_token
   *  expires_in
   *  expires_at
   *  refresh_token
   *  scope
   *  state
   *
   * This is all the information retrieved from the host. You may
   * however, want to use the services' variables
   *
   *  accessToken
   *  refreshToken
   *
   * These variables will always be updated after every call to
   * this function, so make sure to call it.
   *
   * @returns {Object} The token object.
   */
  function loadToken() {
    return token || storeToken();
  }

  /**
   * Sets and returns the token object. It tries the following:
   * - takes the token from the uri parameters
   * - takes the token from the function parameter (if given)
   * - takes the token from the local storage.
   *
   * @param {Object} [tokenObj] The token object to store.
   * @returns {Object} The token object.
   */
  function storeToken(tokenObj) {
    var obj = extractHash(),
        inStorage = false;
    if (obj === null) {
      if (tokenObj) {
        obj = createToken(tokenObj);
      } else if ('oauth-token' in window.localStorage) {
        var storedObj = JSON.parse(window.localStorage['oauth-token']);
        obj = createToken(storedObj);
        if (obj) {
          inStorage = true;
        }
      }
    }
    token = obj;
    if (token) {
      if (!inStorage) {
        oaLog.debug('oaToken::storeToken', 'Storing token ' + token.access_token + ' <-> ' + token.expires_in + ' sec');
        window.localStorage['oauth-token'] = JSON.stringify(token);
      }
      service.accessToken = token.access_token;
      service.refreshToken = token.refresh_token;
    } else {
      clearToken();
    }
    return token;
  }

  /**
   * Deletes the token object.
   */
  function clearToken() {
    service.accessToken = '';
    service.refreshToken = '';
    delete window.localStorage['oauth-token'];
    token = null;
  }

  /**
   * Check if the token object has reached its expiration date. May
   * also return true if there is no token.
   *
   * @returns {Boolean} true if expired.
   */
  function isExpired() {
    return ((token === null) || (token.expires_at < new Date()));
  }

  /**
   * Creates a new object with all the required fields for a valid
   * token. Some fields are optional. If the required fields are not
   * present the function will return null.
   *
   * Required properties:
   * - token_type
   * - access_token
   * - expires_in
   *
   * Optional:
   * - expires_at
   * - refresh_token
   * - scope
   * - state
   *
   * Note: When passing the `expires_at` property make sure that
   *       it is a valid date object.
   *
   * @param {Object} params Object with the token parameters.
   * @returns {Object} The token object
   */
  function createToken(params) {
    if (!hasAttributes(params, required)) {
      return null;
    }
    var obj = _.defaults(params, optional);
    return setExpirationDate(obj);
  }

  /**
   * Read the hash parameters. If the required parameters to create
   * a token are found then all the possible parameters to create a
   * token will be removed from the location hash, and new token will
   * be returned. Otherwise the location hash is left untouched
   * and the function will return null.
   *
   * @returns {Object} A valid token or null.
   */
  function extractHash() {
    var query = oaHash.get();
    var obj = createToken(query);
    if (obj) {
      oaLog.debug('oaToken::extractHash', 'Token was found in url');
      // The following line will change the hash and the page will reload.
      oaHash.del.apply(this, required.concat(_.keys(optional)));
    }
    return obj;
  }

  /**
   * Set the expiration date on the input object. Note that
   * the input should have the attribute `expires_in` and optionally
   * `expires_at`.
   *
   * @param {Object} obj The object to modify.
   * @returns {*}
   */
  function setExpirationDate(obj) {
    if (obj.expires_at) {
      obj.expires_at = new Date(obj.expires_at);
    } else {
      var expires_at = new Date(),
          seconds = expires_at.getSeconds() + parseInt(obj.expires_in);
      expires_at.setSeconds(seconds);
      obj.expires_at = expires_at;
    }
    return obj;
  }

}
