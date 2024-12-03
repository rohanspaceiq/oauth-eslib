angular.module('oauth', []);

/**
 * Check if the input object has all the keys specified in the
 * array of `attributes`.
 *
 * @param {Object} obj The object in question.
 * @param {Array} attributes The required attributes.
 * @returns {boolean}
 */
function hasAttributes(obj, attributes) {
  var intersection = _.intersection(_.keys(obj), attributes);
  return intersection.length == attributes.length;
}

