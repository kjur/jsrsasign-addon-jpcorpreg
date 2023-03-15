const VERSION = "0.9.1";
const VERSION_FULL = "jsrsasign-addon-jpcorpreg 0.9.1 (c) Kenji Urushima github.com/kjur/jsrsasign-addon-jpcorpreg";

const OIDs = {
    "certificatePoliciesJP":		"1.2.392.100300.1.1.1",
    "registrarJP":			"1.2.392.100300.1.1.2",
    "registeredCorporationInfoJP":	"1.2.392.100300.1.1.3"
};

let _KJUR = null;
let _X509 = null;
let _ASN1HEX = null;

function register(jsrsasign) {
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
	let result = {
	    extname: _KJUR.asn1.x509.OID.oid2name(oid)
	};

	let pPIs = pASN1.seq.map((elem) => {
	    let pPI = {};
	    pPI.policyoid = elem.seq[0].oid;
	    try {
		let pPQs = _asn12PQs(elem.seq[1].seq);
		pPI.array = pPQs;
	    } catch(ex2) {};
	    return pPI;
	});
	result.array = pPIs;
	if (critical) result.critical = true;
	return result;
    } catch(ex) {
	return undefined;
    }
}

function extParserRegistrarJP(oid, critical, hExtV) {
    try {
	let pExtV = _ASN1HEX.parse(hExtV);
	let pDispText = _asn12DispText(pExtV);
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
	pExtV.seq.map((elem) => {
	    let tagValue = _isset(elem, 'tag.tag');
	    let tagName = CORPINFO_TAG[tagValue];
	    let pDirStr = _isset(elem, 'tag.obj');
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

function _asn12PQs(asn1PQs) {
    let pPQs = asn1PQs.map((elem) => {
	let type = elem.seq[0].oid;
	if (type == "1.3.6.1.5.5.7.2.2") {
	    return { unotice: _asn12Unotice(elem.seq[1].seq) };
	}
	return null;
    });
    pPQs = pPQs.filter((elem) => elem != null);
    return pPQs;
}

function _asn12DispText(pASN1) {
    if (pASN1.utf8str != undefined) return { type: "utf8", str: pASN1.utf8str.str };
    if (pASN1.prnstr != undefined) return { type: "prn", str: pASN1.prnstr.str };
    return null;
}

function _asn12Noticenum(aASN1) {
    let pNoticenum = aASN1.seq.map((elem) => {
	if (elem.int != undefined) return elem.int;
	return null;
    });
    pNoticenum = pNoticenum.filter((elem) => elem != null);
    return pNoticenum;
}

function _asn12Unotice(aASN1Unotice) {
    let pUnotice = {};
    aASN1Unotice.map((elem) => {
	if (elem.seq != undefined) {
	    pUnotice.noticeref = {
		org: _asn12DispText(elem.seq[0]),
		noticenum: _asn12Noticenum(elem.seq[1])
	    };
	    return;
	}
	let pDispText = _asn12DispText(elem);
	if (pDispText != null) {
	    pUnotice.exptext = pDispText;
	    return;
	}
    });
    return pUnotice;
}

function _dirstr(pDirStr) {
    if (typeof pDirStr != "object") return undefined;
    let aType = ["utf8str", "prnstr", "telstr", "bmpstr"];
    let result;
    aType.map(type => {
	let value = _isset(pDirStr, `${type}.str`);
	if (value != undefined) result = value;
    });
    return result;
}

function _isset(val, keys, def) {
    var keys = String(keys).split('.');
    for (var i = 0; i < keys.length && val; i++) {
	var key = keys[i];
	if (key.match(/^[0-9]+$/)) key = parseInt(key);
        val = val[key];
    }
    return val || val === false ? val : def;
}

exports.VERSION = VERSION;
exports.VERSION_FULL = VERSION_FULL;
exports.OIDs = OIDs;
exports.register = register;
exports.registerParts = registerParts;
exports.extParserRegistrarJP = extParserRegistrarJP;
exports.extParseJCertificatePolicy = extParseJCertificatePolicy;
exports.extParseRegisteredCorpInfo = extParseRegisteredCorpInfo;
