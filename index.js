const VERSION = "0.9.2";
const VERSION_FULL = "jsrsasign-addon-jpcorpreg 0.9.2 (c) Kenji Urushima github.com/kjur/jsrsasign-addon-jpcorpreg";

const OIDs = {
    "certificatePoliciesJP":		"1.2.392.100300.1.1.1",
    "registrarJP":			"1.2.392.100300.1.1.2",
    "registeredCorporationInfoJP":	"1.2.392.100300.1.1.3"
};

let _jsrsasign = null;
let _KJUR = null;
let _X509 = null;
let _ASN1HEX = null;

function register(jsrsasign) {
    _jsrsasign = jsrsasign;
    registerParts(jsrsasign.KJUR, jsrsasign.X509, jsrsasign.ASN1HEX);
}

function registerParts(argKJUR, argX509, argASN1HEX) {
    _KJUR = argKJUR;
    _X509 = argX509;
    _ASN1HEX = argASN1HEX;
    _KJUR.asn1.x509.OID.registerOIDs(OIDs);
    _X509.registExtParser("1.2.392.100300.1.1.1", extParseJCertificatePolicy);
    _X509.registExtParser("1.2.392.100300.1.1.2", extParserRegistrarJP);
    _X509.registExtParser("1.2.392.100300.1.1.3", extParseRegisteredCorpInfo);
}

function extParseJCertificatePolicy(oid, critical, hExtV) {
    try {
	let pASN1 = _ASN1HEX.parse(hExtV);
	let x = new _X509();
	let pExtV = x.getExtCertificatePolicies(hExtV, critical);
	let result = {
	    extname: _KJUR.asn1.x509.OID.oid2name(oid),
	    array: pExtV.array
	};
	if (critical) result.critical = true;
	return result;
    } catch(ex) {
	return undefined;
    }
}

function extParserRegistrarJP(oid, critical, hExtV) {
    try {
	let pExtV = _ASN1HEX.parse(hExtV);
	let x = new _X509();
	let pDispText = x.asn1ToDisplayText(pExtV);
	if (pDispText == null) throw new Error("improper extn value");
	let result = {
	    extname: _KJUR.asn1.x509.OID.oid2name(oid),
	    value: pDispText.str
	};
	if (critical) result.critical = true;
	return result;
    } catch(ex) {
	return undefined;
    }
}

const CORPINFO_TAG = {
    "a0": "corporateName",
    "a1": "registeredNumber",
    "a2": "corporateAddress",
    "a3": "directorName",
    "a4": "directorTitle",
    "a6": "registryOffice"
};

function extParseRegisteredCorpInfo(oid, critical, hExtV) {
    try {
	let pExtV = _ASN1HEX.parse(hExtV);
	let aTypeValue = [];
	let pValue = {};
	let x = new _X509();
	pExtV.seq.map((elem) => {
	    let tagValue = _jsrsasign.aryval(elem, 'tag.tag');
	    let tagName = CORPINFO_TAG[tagValue];
	    let pDirStr = _jsrsasign.aryval(elem, 'tag.obj');
	    if (tagName == undefined || pDirStr == undefined) return;
	    let dirStr = _dirstr(pDirStr);
	    if (dirStr == undefined) return;
	    pValue[tagName] = dirStr;
	});

	let result = {
	    extname: _KJUR.asn1.x509.OID.oid2name(oid),
	    value: pValue
	};
	if (critical) result.critical = true;
	return result;
    } catch(ex) {
	return undefined;
    }
}

function _dirstr(pDirStr) {
    if (typeof pDirStr != "object") return undefined;
    let aType = ["utf8str", "prnstr", "telstr", "bmpstr"];
    let result;
    aType.map(type => {
	let value = _jsrsasign.aryval(pDirStr, `${type}.str`);
	if (value != undefined) result = value;
    });
    return result;
}

exports.VERSION = VERSION;
exports.VERSION_FULL = VERSION_FULL;
exports.OIDs = OIDs;
exports.register = register;
exports.registerParts = registerParts;
exports.extParserRegistrarJP = extParserRegistrarJP;
exports.extParseJCertificatePolicy = extParseJCertificatePolicy;
exports.extParseRegisteredCorpInfo = extParseRegisteredCorpInfo;
