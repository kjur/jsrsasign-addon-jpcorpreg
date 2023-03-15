var assert = require('assert');
var rs = require("jsrsasign");
require('../index.js').register(rs);

describe("check custom extension parser definitions", function() {
    let equal = assert.equal;
    it("test", function() {
	equal(typeof rs.X509.EXT_PARSER["1.2.392.100300.1.1.1"], "function");
	equal(typeof rs.X509.EXT_PARSER["1.2.392.100300.1.1.2"], "function");
	equal(typeof rs.X509.EXT_PARSER["1.2.392.100300.1.1.3"], "function");
    });
});