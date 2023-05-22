(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
      // AMD. Register as an anonymous module.
      define([], factory);
  } else if (typeof module === 'object' && module.exports) {
      // Node. Does not work with strict CommonJS, but
      // only CommonJS-like environments that support module.exports,
      // like Node.
      module.exports = factory();
  } else {
      // Browser globals (root is window)
      root.CMAC = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  // Your class definition here
  class CMAC {
  
    constructor() {
      if (typeof window === "undefined") {
        // Node.js
        this.crypto = require("crypto");
        // new CMAC(crypto);
      } else {
        // Browser
        this.crypto=window.crypto.subtle;
      }
      // this.crypto = crypto;
      this.key = null;
      this.tLen = 4;
      this.blockSize = 16; // AES block size
      this.algorithm =  "aes-128-cbc";
      this.subKeys = null;
    }
    toUint8Array(hex) {
      return new Uint8Array(
        hex.match(/[\da-f]{2}/gi).map(function (h) {
          return parseInt(h, 16);
        })
      );
    }
    // ----- FASTEST Uint8Array to HEX String
    // End Pre-Init
    toHex(buffer) {
      // Pre-Init
      const LUT_HEX_4b = [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
      ];
      const LUT_HEX_8b = new Array(0x100);
      for (let n = 0; n < 0x100; n++) {
        LUT_HEX_8b[n] = `${LUT_HEX_4b[(n >>> 4) & 0xf]}${LUT_HEX_4b[n & 0xf]}`;
      }
      let out = "";
      for (let idx = 0, edx = buffer.length; idx < edx; idx++) {
        out += LUT_HEX_8b[buffer[idx]];
      }
      return out;
    }
  
    async init(key, algorithm = "aes-128-ecb", tLen) {
      this.key = key;
      this.tLen = tLen;
      this.blockSize = 16; // AES block size
      this.algorithm = algorithm;
      this.subKeys = await this.generateSubKeys();
    }
  
    async generateSubKeys() {
      let zeroBlock = new Uint8Array(this.blockSize, 0);
      let L; //= crypto.createCipheriv(`aes-${this.key.length*8}-ecb`, this.key, null).update(zeroBlock);
      if (typeof window === "undefined") {
        // Node.js
        L = this.crypto
          .createCipheriv(`aes-${this.key.length * 8}-cbc`, this.key, zeroBlock)
          .update(zeroBlock);
      } else {
        // Browser
        let key = await this.crypto.importKey(
          "raw",
          this.key,
          "AES-CBC",
          false,
          ["encrypt"]
        );
        L = new Uint8Array(
          await this.crypto.encrypt(
            { name: "AES-CBC", iv: new Uint8Array(this.blockSize) },
            key,
            zeroBlock
          )
        );
      }
  
      let K1 = this.leftShift(L);
      if (L[0] & 0x80) {
        K1[K1.length - 1] ^= 0x87;
      }
  
      let K2 = this.leftShift(K1);
      if (K1[0] & 0x80) {
        K2[K2.length - 1] ^= 0x87;
      }
  
      return { K1, K2 };
    }
  
    leftShift(buffer) {
      buffer = new Uint8Array(buffer);
      let shifted = new Uint8Array(buffer.length);
      let carry = 0;
      for (let i = buffer.length - 1; i >= 0; i--) {
        let val = buffer[i] << 1;
        shifted[i] = (val & 0xff) | carry;
        carry = val & 0x100 ? 1 : 0;
      }
      return shifted;
    }

    
// Function to add zero padding
zeroPad(data) {
  let padding = this.blockSize - (data.length % this.blockSize);
  let paddedData = new Uint8Array(data.length + padding);
  paddedData.set(data);
  // Fill the rest of the buffer with zeros
  paddedData.fill(0, data.length);
  return paddedData;
}

// Function to remove zero padding
zeroUnpad(data) {
  // Find the last non-zero byte
  let paddingStart = data.length;
  while (paddingStart > 0 && data[paddingStart - 1] === 0) {
      paddingStart--;
  }
  // Return the data up to the start of the padding
  return data.slice(0, paddingStart);
}

  // Function to add PKCS#7 padding
  pkcs7Pad(data) {
    let padding = 16 - (data.length % 16);
    let paddedData = new Uint8Array(data.length + padding);
    paddedData.set(data);
    paddedData.fill(padding, data.length);
    return paddedData;
}

// Function to remove PKCS#7 padding
pkcs7Unpad(data) {
  let padding = data[data.length - 1];
  return data.slice(0, data.length - padding);
}
// Function to add OneZero padding
oneZeroPad(data) {
  let padding = 16 - (data.length % 16);
  let paddedData = new Uint8Array(data.length + padding);
  paddedData.set(data);
  paddedData[data.length] = 0x80; // Set first padding byte to '10000000'
  return paddedData;
}

// Function to remove OneZero padding
oneZeroUnpad(data) {
  let paddingStart = data.length - 1;
  while (data[paddingStart] === 0) {
      paddingStart--;
  }
  // Check if the padding start byte is '10000000'
  if (data[paddingStart] !== 0x80) {
      console.error("Invalid padding");
  }
  return data.slice(0, paddingStart);
}


async compute(data) {
  // Initialize variables
  let n;
  let M;

  // If data length is 0, create a new Uint8Array with blockSize and set the first byte to 0x80
  // Then XOR each byte of M with the corresponding byte of K2
  if (data.length === 0) {
    n = 1;
    M = new Uint8Array(this.blockSize, 0);
    M[0] = 0x80;
    for (let i = 0; i < this.blockSize; i++) {
      M[i] ^= this.subKeys.K2[i];
    }
  } else {
    // If data length is not 0, calculate the number of blocks needed to store the data
    // Create a new Uint8Array with enough space for all blocks
    // Copy the data into M
    n = Math.ceil(data.length / this.blockSize);
    M = new Uint8Array(n * this.blockSize);
    M.set(data);

    // If data length is a multiple of blockSize, XOR each byte of the last block of M with the corresponding byte of K1
    // If data length is not a multiple of blockSize, set the first byte after the data to 0x80 and XOR each byte of the last block of M with the corresponding byte of K2
    if (data.length % this.blockSize === 0) {
      for (let i = 0; i < this.blockSize; i++) {
        M[(n - 1) * this.blockSize + i] ^= this.subKeys.K1[i];
      }
    } else {
      M[data.length] = 0x80;
      for (let i = 0; i < this.blockSize; i++) {
        M[(n - 1) * this.blockSize + i] ^= this.subKeys.K2[i];
      }
    }
  }

  // Initialize C as a new Uint8Array with blockSize
  let C = new Uint8Array(this.blockSize);

  // For each block in M, XOR each byte of C with the corresponding byte of the block
  // Then encrypt C using AES-CBC with the key and a zero IV
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < this.blockSize; j++) {
      C[j] ^= M[i * this.blockSize + j];
    }

    // Use Node.js crypto module if running in Node.js, or Web Crypto API if running in a browser
    if (typeof window === "undefined") {
      // Node.js
      C = this.crypto
        .createCipheriv(`aes-${this.key.length * 8}-cbc`, this.key, new Uint8Array(this.blockSize))
        .update(C);
    } else {
      // Browser
      let key = await this.crypto.importKey(
        "raw",
        this.key,
        "AES-CBC",
        false,
        ["encrypt"]
      );
      C = new Uint8Array(
        await this.crypto.encrypt(
          { name: "AES-CBC", iv: new Uint8Array(this.blockSize) },
          key,
          C
        )
      );
    }
  }

  // If tLen is set, return the first tLen bytes of C
  // Otherwise, return C
  if (this.tLen) {
    return C.slice(0, this.tLen);
  } else {
    return C;
  }
}
    async verify(data, cmac) {
      let computedCmac = await this.compute(data);
      return computedCmac.equals(cmac) ? true : false;
    }
  }

  // Return your class
  return CMAC;
}));

