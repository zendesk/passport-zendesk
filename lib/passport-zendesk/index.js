'use strict';

/**
 * Module dependencies.
 */
var Strategy = require('./strategy');

/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;