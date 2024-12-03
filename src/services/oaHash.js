angular.module('oauth')
    .factory('oaHash', ['$location', oaHash]);

/**
 * The `oaHash` service provides functions to parse and compose query
 * parameters. These are used in combination with the `$location`
 * service to obtain the hash parameters in the application.
 */
function oaHash($location) {
  return {
    get: get,
    set: set,
    del: del,
    extend: extend,
    parse: parse,
    compose: compose
  };

  /**
   * Returns an object containing the hash parameters specified in
   * the current url.
   *
   * @returns {Object} A parameters if any, otherwise null.
   */
  function get() {
    return parse($location.hash());
  }


  /**
   * Sets the hash parameters in the current location from an object.
   * For instance, calling `oauth.set({a: 1, b: 2})` will make the
   * next call for `$location.hash()` return `a=1&b=2`.
   *
   * @param {Object} query The object with the query parameters.
   * @returns {Object} The object parameter.
   */
  function set(query) {
    $location.hash(compose(query));
    return query;
  }

  /**
   * Deletes parameters by name.
   *
   * @param {...String} [arguments] keys/properties to be deleted.
   * @returns {Object} The new parameters in the hash.
   */
  function del() {
    var params = get() || {};
    for (var i = 0, ii = arguments.length; i < ii; i++) {
      delete params[arguments[i]];
    }
    return set(params);
  }


  /**
   * Extends the hash parameters by copying properties from the
   * given parameter(s).
   *
   * @param {...String} [arguments] object(s).
   * @returns {Object} The new parameters in the hash.
   */
  function extend() {
    var args = Array.prototype.slice.call(arguments);  // Get arguments as array
    args.unshift(get() || {});                         // Prepend current parameters
    return set(angular.extend.apply(this, args));
  }

  /**
   * Parses a string in the form `a=1&b=2...` and builds an object
   * from the parsed information. If the object to be returned is
   * empty then the returned value will be null. If you must
   * always obtain an object you may do
   *
   * `oaHash.parse(query) || {}`.
   *
   * Note: Checking if the result is null informs us quickly that the
   * query was empty. No need to check if the object has properties.
   *
   * @param {String} query The uri query string parameters.
   * @returns {Object} The parameters if any, otherwise null.
   */
  function parse(query) {
    var pair, result = {},
        empty = true,
        vars = query.split('&');
    for (var i = 0; i < vars.length; i++) {
      pair = vars[i].split('=');
      if (pair[0] !== '') {
        empty = false;
        result[pair[0]] = decodeURIComponent(pair[1]);
      }
    }
    return (empty ? null : result);
  }

  /**
   * Generates a string in the form of uri query parameters.
   * For instance, the object `{a: 1, b: 2}` will generate
   * the string `a=1&b=2`.
   *
   * @param {Object} query The object with the parameters.
   * @returns {String} A valid URI query parameters string.
   */
  function compose(query) {
    return Object.keys(query).map(function(value) {
      return value + "=" + encodeURIComponent(query[value]);
    }).join('&');
  }

}
