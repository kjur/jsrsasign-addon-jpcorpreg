var assert = require('assert');
var rs = require("jsrsasign");
var addon1 = require('../index.js');
addon1.register(rs);

describe("registrarJP extension handler", function() {
    let deepEqual = assert.deepEqual;
    it("test", function() {
	let pExpect;
	hIn = "0c18e69db1e4baace6b395e58b99e5b180e799bbe8a898e5ae98";
	pExpect = {
	    extname: "registrarJP",
	    critical: true,
	    value: "東京法務局登記官"
	};
	deepEqual(addon1.extParserRegistrarJP("1.2.392.100300.1.1.2", true, hIn), pExpect);
    });
});
