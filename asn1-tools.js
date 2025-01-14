// Copyright 2018 AJ ONeal. All rights reserved
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// modified in 2024-01 by Arno Richter, https://arnorichter.de
// combined the parser and packer into a single ES module

var ASN1 = {};
var Enc = {};
var PEM = {};

//
// Parser
//

// Although I've only seen 9 max in https certificates themselves,
// but each domain list could have up to 100
ASN1.ELOOPN = 102;
ASN1.ELOOP = "uASN1.js Error: iterated over " + ASN1.ELOOPN + "+ elements (probably a malformed file)";
// I've seen https certificates go 29 deep
ASN1.EDEEPN = 60;
ASN1.EDEEP = "uASN1.js Error: element nested " + ASN1.EDEEPN + "+ layers deep (probably a malformed file)";
// Container Types are Sequence 0x30, Container Array? (0xA0, 0xA1)
// Value Types are Boolean 0x01, Integer 0x02, Null 0x05, Object ID 0x06, String 0x0C, 0x16, 0x13, 0x1e Value Array? (0x82)
// Bit String (0x03) and Octet String (0x04) may be values or containers
// Sometimes Bit String is used as a container (RSA Pub Spki)
ASN1.CTYPES = [ 0x30, 0x31, 0xa0, 0xa1 ];
ASN1.VTYPES = [ 0x01, 0x02, 0x05, 0x06, 0x0c, 0x82 ];
ASN1.parse = function parseAsn1Helper(buf) {

	function parseAsn1(buf, depth, eager) {
		if (depth.length >= ASN1.EDEEPN) { throw new Error(ASN1.EDEEP); }

		var index = 2; // we know, at minimum, data starts after type (0) and lengthSize (1)
		var asn1 = { type: buf[0], lengthSize: 0, length: buf[1] };
		var child;
		var iters = 0;
		var adjust = 0;
		var adjustedLen;

		// Determine how many bytes the length uses, and what it is
		if (0x80 & asn1.length) {
			asn1.lengthSize = 0x7f & asn1.length;
			// I think that buf->hex->int solves the problem of Endianness... not sure
			asn1.length = parseInt(Enc.bufToHex(buf.slice(index, index + asn1.lengthSize)), 16);
			index += asn1.lengthSize;
		}

		// High-order bit Integers have a leading 0x00 to signify that they are positive.
		// Bit Streams use the first byte to signify padding, which x.509 doesn't use.
		if (0x00 === buf[index] && (0x02 === asn1.type || 0x03 === asn1.type)) {
			// However, 0x00 on its own is a valid number
			if (asn1.length > 1) {
				index += 1;
				adjust = -1;
			}
		}
		adjustedLen = asn1.length + adjust;

		//console.warn(depth.join(ws) + '0x' + Enc.numToHex(asn1.type), index, 'len:', asn1.length, asn1);

		function parseChildren(eager) {
			asn1.children = [];
			//console.warn('1 len:', (2 + asn1.lengthSize + asn1.length), 'idx:', index, 'clen:', 0);
			while (iters < ASN1.ELOOPN && index < (2 + asn1.length + asn1.lengthSize)) {
				iters += 1;
				depth.length += 1;
				child = parseAsn1(buf.slice(index, index + adjustedLen), depth, eager);
				depth.length -= 1;
				// The numbers don't match up exactly and I don't remember why...
				// probably something with adjustedLen or some such, but the tests pass
				index += (2 + child.lengthSize + child.length);
				//console.warn('2 len:', (2 + asn1.lengthSize + asn1.length), 'idx:', index, 'clen:', (2 + child.lengthSize + child.length));
				if (index > (2 + asn1.lengthSize + asn1.length)) {
					if (!eager) { console.error(JSON.stringify(asn1, ASN1._replacer, 2)); }
					throw new Error("Parse error: child value length (" + child.length
						+ ") is greater than remaining parent length (" + (asn1.length - index)
						+ " = " + asn1.length + " - " + index + ")");
				}
				asn1.children.push(child);
				//console.warn(depth.join(ws) + '0x' + Enc.numToHex(asn1.type), index, 'len:', asn1.length, asn1);
			}
			if (index !== (2 + asn1.lengthSize + asn1.length)) {
				//console.warn('index:', index, 'length:', (2 + asn1.lengthSize + asn1.length));
				throw new Error("premature end-of-file");
			}
			if (iters >= ASN1.ELOOPN) { throw new Error(ASN1.ELOOP); }

			delete asn1.value;
			return asn1;
		}

		// Recurse into types that are _always_ containers
		if (-1 !== ASN1.CTYPES.indexOf(asn1.type)) { return parseChildren(eager); }

		// Return types that are _always_ values
		asn1.value = buf.slice(index, index + adjustedLen);
		if (-1 !== ASN1.VTYPES.indexOf(asn1.type)) { return asn1; }

		// For ambigious / unknown types, recurse and return on failure
		// (and return child array size to zero)
		try { return parseChildren(true); }
		catch(e) { asn1.children.length = 0; return asn1; }
	}

	var asn1 = parseAsn1(buf, []);
	var len = buf.byteLength || buf.length;
	if (len !== 2 + asn1.lengthSize + asn1.length) {
		throw new Error("Length of buffer does not match length of ASN.1 sequence.");
	}
	return asn1;
};
ASN1._replacer = function (k, v) {
	if ('type' === k) { return '0x' + Enc.numToHex(v); }
	if (v && 'value' === k) { return '0x' + Enc.bufToHex(v.data || v); }
	return v;
};

//
// Packer
//

ASN1.newASN1 = function newASN1(/*type, hexstrings...*/) {
	var args = Array.prototype.slice.call(arguments);
	var typ = args.shift();
	var str = args.join('').replace(/\s+/g, '').toLowerCase();
	var len = (str.length/2);
	var lenlen = 0;
	var hex = typ;

	// We can't have an odd number of hex chars
	if (len !== Math.round(len)) {
		throw new Error("invalid hex");
	}

	// The first byte of any ASN.1 sequence is the type (Sequence, Integer, etc)
	// The second byte is either the size of the value, or the size of its size

	// 1. If the second byte is < 0x80 (128) it is considered the size
	// 2. If it is > 0x80 then it describes the number of bytes of the size
	//    ex: 0x82 means the next 2 bytes describe the size of the value
	// 3. The special case of exactly 0x80 is "indefinite" length (to end-of-file)

	if (len > 127) {
		lenlen += 1;
		while (len > 255) {
			lenlen += 1;
			len = len >> 8;
		}
	}

	if (lenlen) { hex += Enc.numToHex(0x80 + lenlen); }
	return hex + Enc.numToHex(str.length/2) + str;
};

// The Integer type has some special rules
ASN1.UInt = function UINT() {
	var str = Array.prototype.slice.call(arguments).join('');
	var first = parseInt(str.slice(0, 2), 16);

	// If the first byte is 0x80 or greater, the number is considered negative
	// Therefore we add a '00' prefix if the 0x80 bit is set
	if (0x80 & first) { str = '00' + str; }

	return ASN1.newASN1('02', str);
};

// The Bit String type also has a special rule
ASN1.BitStr = function BITSTR() {
	var str = Array.prototype.slice.call(arguments).join('');
	// '00' is a mask of how many bits of the next byte to ignore
	return ASN1.newASN1('03', '00' + str);
};

ASN1.pack = function (arr) {
	var typ = Enc.numToHex(arr[0]);
	var str = '';
	if (Array.isArray(arr[1])) {
		arr[1].forEach(function (a) {
			str += ASN1.pack(a);
		});
	} else if ('string' === typeof arr[1]) {
		str = arr[1];
	} else {
		throw new Error("unexpected array");
	}
	if ('03' === typ) {
		return ASN1.BitStr(str);
	} else if ('02' === typ) {
		return ASN1.UInt(str);
	} else {
		return ASN1.newASN1(typ, str);
	}
};

// don't replace the full parseBlock, if it exists
PEM.parseBlock = PEM.parseBlock || function (str) {
	var der = str.split(/\n/).filter(function (line) {
		return !/-----/.test(line);
	}).join('');
	return { der: Enc.base64ToBuf(der) };
};

PEM.packBlock = function (opts) {
	// TODO allow for headers?
	return '-----BEGIN ' + opts.type + '-----\n'
		+ Enc.bufToBase64(opts.bytes).match(/.{1,64}/g).join('\n') + '\n'
		+ '-----END ' + opts.type + '-----'
	;
};

Enc.base64ToBuf = function (b64) {
	return Enc.binToBuf(atob(b64));
};
Enc.bufToBase64 = function (u8) {
	var bin = '';
	u8.forEach(function (i) {
		bin += String.fromCharCode(i);
	});
	return btoa(bin);
};
Enc.binToBuf = function (bin) {
	var arr = bin.split('').map(function (ch) {
		return ch.charCodeAt(0);
	});
	return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
};
Enc.bufToHex = function (u8) {
	var hex = [];
	var i, h;
	var len = (u8.byteLength || u8.length);

	for (i = 0; i < len; i += 1) {
		h = u8[i].toString(16);
		if (h.length % 2) { h = '0' + h; }
		hex.push(h);
	}

	return hex.join('').toLowerCase();
};
Enc.hexToBuf = function (hex) {
	var arr = [];
	hex.match(/.{2}/g).forEach(function (h) {
		arr.push(parseInt(h, 16));
	});
	return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
};
Enc.numToHex = function (d) {
	d = d.toString(16);
	if (d.length % 2) {
		return '0' + d;
	}
	return d;
};

export { ASN1, PEM, Enc }
