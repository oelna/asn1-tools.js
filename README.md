# Combined Fork of [asn1-parser.js](https://github.com/coolaj86/asn1-parser.js) and [asn1-packer.js](https://github.com/coolaj86/asn1-packer.js)

I combined the two libraries into a single ESM. Hope I didn't break anything. Original code by @coolaj86

# Usage

```js
import { ASN1, PEM, Enc } from './asn1-tools.js';

// PARSE
var pem = [ '-----BEGIN EC PRIVATE KEY-----'
          + 'MHcCAQEEIImMnaNu2jRjvQwVFnhhDw/KDYtS2Q6n8T5kJYniwY1UoAoGCCqGSM49'
          + 'AwEHoUQDQgAEIT1SWLxsacPiE5Z16jkopAn8/+85rMjgyCokrnjDft6Y/YnA4A50'
          + 'yZe7CnFsqeDcpnPbubP6cpYiVcnevNIYyg=='
          + '-----END EC PRIVATE KEY-----'
          ].join('\n');

var der = PEM.parseBlock(pem).der;
var json = ASN1.parse(der);

console.log(json);

// PACK
var arr = [
  0x30,
  [
    [ 0x30, [ [ 0x06, "2a8648ce3d0201" ], [ 0x06, "2a8648ce3d030107" ] ] ],
    [ 0x03, "04213d5258bc6c69c3e2139675ea3928a409fcffef39acc8e0c82a24ae78c37ede98fd89c0e00e74c997bb0a716ca9e0dca673dbb9b3fa72962255c9debcd218ca" ]
  ]
];

var hex = ASN1.pack(arr);
var buf = Enc.hexToBuf(hex);
var pem = PEM.packBlock({ type: "PUBLIC KEY", bytes: buf });

console.log(pem);
```

### Optimistic Parsing

This is a dumbed-down, minimal ASN1 parser.

Rather than incorporating knowledge of each possible x509 schema
to know whether to traverse deeper into a value container,
it always tries to dive in (and backs out when parsing fails).

It is possible that it will produce false positives, but not likely
in real-world scenarios (PEM, x509, CSR, etc).

### Zero Dependencies

Rather than requiring hundreds (or thousands) of lines of dependencies,
this library takes the approach of including from other libraries in its suite
to produce a small, focused file that does exactly what it needs to do.

# Legal

[Bluecrypt VanillaJS ASN.1 Parser](https://git.coolaj86.com/coolaj86/asn1-parser.js) | MPL-2.0
