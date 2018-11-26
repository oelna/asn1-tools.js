# BlueCrypt ASN.1 Parser

An ASN.1 parser in less than 100 lines of Vanilla JavaScript,
part of the BlueCrypt suite.
<br>
<small>(< 150 with newlines and comments)</small>

| < 100 lines of code | 1.1k gzipped | 2.5k minified | 4.7k with comments |

# Features

* [x] Complete ASN.1 parser
  * [x] Parses x.509 certificates
  * [x] PEM (base64-encoded DER)
* [x] VanillaJS, Zero Dependencies
  * [x] Browsers (back to ES5.1)
  * [ ] Node.js (built, publishing soon)
  * [ ] Online Demo (built, publishing soon)

![](https://i.imgur.com/gV7w7bM.png)

<!--
# Demo

<https://coolaj86.com/demos/asn1-parser/>
-->

# Usage

```html
<script src="https://git.coolaj86.com/coolaj86/asn1-parser.js/raw/branch/master/asn1-parser.js"></script>
```

```js
'use strict";

var ASN1 = window.ASN1  // 62 lines
var Enc = window.Enc    // 27 lines
var PEM = window.PEM    //  6 lines

var pem = [ '-----BEGIN EC PRIVATE KEY-----'
          + 'MHcCAQEEIImMnaNu2jRjvQwVFnhhDw/KDYtS2Q6n8T5kJYniwY1UoAoGCCqGSM49'
          + 'AwEHoUQDQgAEIT1SWLxsacPiE5Z16jkopAn8/+85rMjgyCokrnjDft6Y/YnA4A50'
          + 'yZe7CnFsqeDcpnPbubP6cpYiVcnevNIYyg=='
          + '-----END EC PRIVATE KEY-----'
          ].join('\n');

var der = PEM.parseBlock(pem).der;
var json = ASN1.parse(der);

console.log(json);
```

```json
{ "type": 48 /*0x30*/, "lengthSize": 0, "length": 89
, "children": [
    { "type": 48 /*0x30*/, "lengthSize": 0, "length": 19
		, "children": [
        { "type": 6, "lengthSize": 0, "length": 7, "value": <0x2a8648ce3d0201> },
        { "type": 6, "lengthSize": 0, "length": 8, "value": <0x2a8648ce3d030107> }
      ]
    },
    { "type": 3, "lengthSize": 0, "length": 66,
      "value": "<0x04213d5258bc6c69c3e2139675ea3928a409fcffef39acc8e0c82a24ae78c37ede98fd89c0e00e74c997bb0a716ca9e0dca673dbb9b3fa72962255c9debcd218ca>"
    }
  ]
}
```

Note: `value` will be a `Uint8Array`, not a hex string.

### Optimistic Parsing

This is a dumbed-down, minimal ASN1 parser.

Rather than incorporating knowledge of each possible x509 schema
to know whether to traverse deeper into a value container,
it always tries to dive in (and backs out when parsing fails).

It is possible that it will produce false positives, but not likely
in real-world scenarios (PEM, x509, CSR, etc).

I'd be interested to hear if you encounter such a case.

### Zero Dependencies

> A little copying is better than a little dependency - Golang Proverbs by Rob Pike

Rather than requiring hundreds (or thousands) of lines of dependencies,
this library takes the approach of including from other libraries in its suite
to produce a small, focused file that does exactly what it needs to do.

# Legal

[BlueCrypt VanillaJS ASN.1 Parser](https://git.coolaj86.com/coolaj86/asn1-parser.js) |
MPL-2.0
