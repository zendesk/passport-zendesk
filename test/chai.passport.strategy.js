// This wrapper around chai-passport-strategy is necessary because
// the chai.use() semantics that chai-passport-strategy is using has changed
require('chai-passport-strategy')(module.exports);
