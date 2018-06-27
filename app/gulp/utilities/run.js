/**
 * An anonymouse callback function to run after gulp streams.
 *
 * @callback streamCallback
 */

/**
 * Run command line scripts from gulp
 *
 * @param {Object} exec The exec module
 * @param {string} command The command you want to run
 * @param {streamCallback} callback An optional callback function
 */
module.exports = (exec, command, callback) => {
  const child = exec(command, { maxBuffer: 1024 * 1000 });
  child.stdout.on('data', data => console.log(data));
  child.stderr.on('data', data => console.log(data));
  if (callback) {
    child.on('close', () => callback());
  }
};
