const fs = require('fs');
const CMAC = require("./cmac.js");
async function parseFile(filename) {
  // Read the file
  let data;
  try {
    data = fs.readFileSync(filename, "utf8");
  } catch (err) {
    console.error("Error reading the file:", err);
    return null;
  }

  // Split the data by empty lines
  const blocks = data.split("\r\n\r\n");

  // Define an array to store the parsed data
  const jsonArray = [];

  // Iterate over each block and parse the contents
  for (const block of blocks) {
    // Split the block into lines
    const lines = block.split("\r\n");

    // Create an object to store the parsed values
    const obj = {};

    // Iterate over each line and parse the key-value pairs
    for (const line of lines) {
      if (!line.startsWith("#")) {
        const [key, value] = line.split(" = ");
        if (value) {
          obj[key.trim()] = value.trim();
        }
      }
    }

    // Add the object to the JSON array
    if (Object.keys(obj).length != 0) {
      jsonArray.push(obj);
    }
  }

  // Return the jsonArray
  return jsonArray;
}

(async () => {
  
  const aesLength = ["128", "192", "256"];
  for (let i = 0; i < aesLength.length; i++) {
    const jsonArray = await parseFile(
      `./testVectors/CMACGenAES${aesLength[i]}.rsp`
    );
    for (let test of jsonArray) {
      let key = Buffer.from(test.Key, "hex");
      let msg =
        test.Msg === "00" ? Buffer.alloc(0) : Buffer.from(test.Msg, "hex");
      let expectedMac = Buffer.from(test.Mac, "hex");

      let cmac = await new CMAC();
      await cmac.init(key, `aes-${aesLength[i]}-ecb`, test.Tlen)
      let mac = await cmac.compute(msg);
      console.log(await cmac.verify(msg, expectedMac));
      // let result = test.Result.substring(0, 1);
      // Truncate the MAC to the expected length
      let verifyResult = (await cmac.verify(msg, expectedMac)) ? "P" : "F";
      // console.log("verify ", result === verifyResult);
      console.log(`mac:${mac.toString("hex")},expectedMac:${test.Mac}`);
    }
  }
})();


