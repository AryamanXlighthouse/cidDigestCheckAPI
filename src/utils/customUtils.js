import { CID } from "multiformats/cid";
import { bases } from "multiformats/basics";
import { readFile } from 'fs/promises';

// Import codecs.json using fs/promises
const codecs = JSON.parse(
  await readFile(
    new URL('../../codecs.json', import.meta.url)
  )
);

// Create a mapping of base prefixes to their corresponding base objects
const basesByPrefix = Object.keys(bases).reduce((acc, curr) => {
  acc[bases[curr].prefix] = bases[curr];
  return acc;
}, {});

// Function to decode a CID value and extract its components
export function decodeCID(value) {
  // Extract the prefix from the CID value
  const prefix = value.substr(0, 1);
  // Get the base object using the prefix
  const base = basesByPrefix[prefix];
  // Parse the CID value using the base object
  const cid = CID.parse(value, base);

  return {
    // Return the decoded CID and its components
    cid,
    multibase: cid.version === 0 ? bases.base58btc : base,
    multicodec: codecs[cid.code],
    multihash: {
      ...cid.multihash,
      name: codecs[cid.multihash.code].name,
    },
  };
}

// Function to process CIDv0 and return the CIDv1 version
export function processCIDv0(inputCid) {
  try {
    // Decode the input CID
    const data = decodeCID(inputCid);
    // Convert CIDv0 to CIDv1
    return data.cid.toV1().toString();
  } catch (err) {
    return { error: err.message || err };
  }
}

// Function to process CIDv1 and return the multihash bytes in the specified base encoding
export function processCIDv1(inputCid) {
  try {
    // Decode the input CID
    const data = decodeCID(inputCid);
    // Encode the multihash bytes in the specified base encoding
    return `DIGEST ${data.multibase.name} MULTIBASE: ${data.multibase.encode(data.multihash.bytes)}`;
  } catch (err) {
    return { error: err.message || err };
  }
}
