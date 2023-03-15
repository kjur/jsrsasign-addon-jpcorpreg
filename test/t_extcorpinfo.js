var assert = require('assert');
var rs = require("jsrsasign");
var addon1 = require('../index.js');
addon1.register(rs);

describe("registeredCorporationInfoJP extension handler", function() {
    let deepEqual = assert.deepEqual;
    it("test", function() {
	let pExpect;
	hIn = "3081aba01a0c18e382b5e383b3e38397e383abe6a0aae5bc8fe4bc9ae7a4bea10e130c303132333435363738393031a2320c30e69db1e4baace983bde6b88be8b0b7e58cbae7a59ee5aeaee5898de4b880e4b881e79baeefbc92e795aaefbc93e58fb7a3140c12e4bd90e897a4e382b5e383b3e38397e383aba4110c0fe4bba3e8a1a8e58f96e7b7a0e5bdb9a6200c1ee69db1e4baace6b395e58b99e5b180e6b88be8b0b7e587bae5bcb5e68980";
	pExpect = {
	    extname: "registeredCorporationInfoJP",
	    critical: true,
	    value: {
		"corporateName": "サンプル株式会社",
		"registeredNumber": "012345678901",
		"corporateAddress": "東京都渋谷区神宮前一丁目２番３号",
		"directorName": "佐藤サンプル",
		"directorTitle": "代表取締役",
		"registryOffice": "東京法務局渋谷出張所"
	    }
	};
	deepEqual(addon1.extParseRegisteredCorpInfo("1.2.392.100300.1.1.3", true, hIn), pExpect);
    });
});
