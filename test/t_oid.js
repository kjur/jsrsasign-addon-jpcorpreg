var assert = require('assert');
var rs = require("jsrsasign");
require('../index.js').register(rs);

describe("registered oid test", function() {
    let equal = assert.equal;
    it("test", function() {
	equal(rs.KJUR.asn1.x509.OID.oid2name("1.2.392.100300.1.1.1"), "certificatePoliciesJP");
	equal(rs.KJUR.asn1.x509.OID.oid2name("1.2.392.100300.1.1.2"), "registrarJP");
	equal(rs.KJUR.asn1.x509.OID.oid2name("1.2.392.100300.1.1.3"), "registeredCorporationInfoJP");
    });
});
