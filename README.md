Sure, here is the README in a code block:

```markdown
# CMAC Library, build using Gpt4

This library provides an implementation of the CMAC (Cipher-based Message Authentication Code) algorithm, which is a versatile cryptographic checksum used for data integrity and authenticity.

## Features

- Supports AES-128, AES-192, and AES-256.
- Works in Node.js and not yet in browser environments.
- No external dependencies.

## Usage

First, import the `CMAC` class from the library:

```javascript
const CMAC = require('./cmac');
```

Then, create a new instance of the `CMAC` class, passing the key, algorithm, and length of the tag as parameters to the constructor:

```javascript
let cmac = await new CMAC();
await cmac.init(key, `aes-${aesLength[i]}-ecb`, test.Tlen)
```

You can then compute the CMAC of a message:

```javascript
let mac = cmac.compute(msg);
```

And verify a CMAC against a message:

```javascript
let isValid = cmac.verify(msg, mac);
```

## Testing

The library comes with a set of test vectors for AES-128, AES-192, and AES-256. You can run these tests using the following code:

```javascript
(async () => {
  const aesLength = ['128', '192', '256'];
  for (let i = 0; i < aesLength.length; i++) {
    const jsonArray = await parseFile(`./testVectors/CMACGenAES${aesLength[i]}.rsp`);
    for (let test of jsonArray) {
      let key = Buffer.from(test.Key, 'hex');
      let msg = test.Msg === '00' ? Buffer.alloc(0) : Buffer.from(test.Msg, 'hex');
      let expectedMac = Buffer.from(test.Mac, 'hex');

      let cmac = new CMAC();
      await cmac.init(key, `aes-${aesLength[i]}-ecb`, test.Tlen);
      let mac = cmac.compute(msg);
      console.log(cmac.verify(msg, expectedMac));

      let verifyResult = cmac.verify(msg, expectedMac) ? 'P' : 'F';
      console.log(`mac:${mac.toString('hex')},expectedMac:${test.Mac}`);
    }
  }
})();
```
```
