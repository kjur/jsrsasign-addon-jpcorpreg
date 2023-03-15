var assert = require('assert');
var rs = require("jsrsasign");
var addon1 = require('../index.js');
addon1.register(rs);

describe("JCertificatePolicy extension handler", function() {
    let deepEqual = assert.deepEqual;
    it("test", function() {
	let pExpect;
	hIn = "30819a30819706092a8308868f4c01030430818930818606082b06010505070202307a30100c09e6b395e58b99e79c8130030201010c66e38193e381aee8a8bce6988ee69bb8e381afe38081e59586e6a5ade799bbe8a898e6b395e3819de381aee4bb96e996a2e4bf82e6b395e4bba4e7ad89e381abe59fbae381a5e3818de799bae8a18ce38195e3828ce3819fe38282e381aee381a7e38199e38082";
	pExpect = {
	    extname: "certificatePoliciesJP",
	    critical: true,
	    array: [{
		policyoid: "1.2.392.100300.1.3.4",
		array: [{
		    unotice: {
			noticeref: {
			    org: {type: "utf8", str: "法務省"},
			    noticenum: [{hex: "01"}]
			},
			exptext: {
			    type: "utf8",
			    str: "この証明書は、商業登記法その他関係法令等に基づき発行されたものです。"
			}
		    }
		}]
	    }]
	};
	deepEqual(addon1.extParseJCertificatePolicy("1.2.392.100300.1.1.1", true, hIn), pExpect);
    });
});
