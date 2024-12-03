angular.module('oauth')
    .factory('oaLog', ['$log', oaLog]);

/**
 * Wrapper around the $log service to handle log messages related
 * to the oauth flow.
 *
 * Example:
 *
 *     oaLog.turnOff();
 *     oaLog.info("testing_context", "this message will not print");
 *
 *     oaLog.turnOn();
 *     oaLog.info("testing_context", "this message will print");
 *
 *     oaLog.disableContext("testing_context");
 *     oaLog.info("testing_context", "will not print");
 *     oaLog.info("other_context", "this will print");
 *
 */
function oaLog($log) {

  var disabled = true,
      contextDisabled = {};

  return {
    turnOff: turnOff,
    turnOn: turnOn,
    enableContext: enableContext,
    disableContext: disableContext,
    log: wrapLog($log.log),
    info: wrapLog($log.info),
    warn: wrapLog($log.warn),
    error: wrapLog($log.error),
    debug: wrapLog($log.debug)
  };

  /**
   * @private
   *
   * Wraps the log function so that a message may be printed when
   * `disabled` is set to false and the specified context is
   * enabled.
   */
  function wrapLog(log) {
    return function(context, msg) {
      if (!disabled && !contextDisabled[context]) {
        log('[' + context + ']: ' + msg);
      }
    };
  }

  /**
   * Disable all messages printed by the oaLog service.
   */
  function turnOff() {
    disabled = true;
  }

  /**
   * Enable the oaLog messages. Some messages may not be displayed if
   * a given context has been disabled.
   */
  function turnOn() {
    disabled = false;
  }

  /**
   * Enable a context so that when it is encountered the message may
   * be printed.
   */
  function enableContext(context) {
    contextDisabled[context] = false;
  }

  /**
   * Disable a context so that messages under that context are not
   * displayed.
   */
  function disableContext(context) {
    contextDisabled[context] = true;
  }

}
