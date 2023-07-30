import { config } from 'dotenv';
config();
import express from 'express';
import cors from 'cors';
import { downloadFileAndExtractHashes } from "./utils/ipfsUtils.js";
import { processCIDv0, processCIDv1 } from "./utils/customUtils.js";
import { checkLinkStatusAndContent } from "./utils/linkCheckUtils.js";

// Retrieve the API key from environment variables
const AUTH_KEY = process.env.AUTH_KEY;
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors()); // Enable CORS
app.use(express.json());

// Middleware to handle the API key
app.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Unauthorized - no authorization header" });
  }
  
  const [authType, authToken] = authHeader.split(' ');
  
  if (authType !== 'Bearer' || authToken !== AUTH_KEY) {
    return res.status(401).json({ error: "Unauthorized - invalid token" });
  }

  next();
});


// Function to display the processed output of a CID
function displayProcessedOutput(inputCid, index) {
  const output0 = processCIDv0(inputCid);
  const output1 = processCIDv1(output0);
  const upperCasedOutput = output1.toUpperCase();
  const indexOfRemoval = upperCasedOutput.indexOf(": ") + 2;
  const processedOutput =
    upperCasedOutput.slice(0, indexOfRemoval) +
    upperCasedOutput.slice(indexOfRemoval + 1);
  
  return `CID ${index}: ${processedOutput}`;
}

// CID processing endpoint
app.post('/processCID', async (req, res) => {
  const { option, inputCid } = req.body;

  if (!option || (option !== "digest" && option !== "list" && option !== "checklink")) {
    return res.status(400).json({ error: "Invalid option. Please provide either 'digest', 'list', or 'checklink' as the first argument." });
  }

  if (option === "digest") {
    if (!inputCid) {
      return res.status(400).json({ error: "CID value is missing. Please provide the CID value as the second argument." });
    }

    try {
      const hashList = await downloadFileAndExtractHashes(inputCid);
      const outputList = [displayProcessedOutput(inputCid, 1)];
      hashList.forEach((cid, index) => {
        outputList.push(displayProcessedOutput(cid, index + 2));
      });

      return res.json({ "List of hash digest:": outputList });
    } catch (error) {
      return res.status(500).json({ error: "Error while fetching the list of CIDs:", details: error });
    }
  } else if (option === "list") {
    if (!inputCid) {
      return res.status(400).json({ error: "CID value is missing. Please provide the CID value as the second argument." });
    }

    try {
      const hashList = await downloadFileAndExtractHashes(inputCid);
      const outputList = [`CID 1: ${inputCid}`];
      hashList.forEach((cid, index) => {
        outputList.push(`CID ${index + 2}: ${cid}`);
      });

      return res.json({ "List of hashes:": outputList });
    } catch (error) {
      return res.status(500).json({ error: "Error while fetching the list of CIDs:", details: error });
    }
  } else if (option === "checklink") {
    if (!inputCid) {
      return res.status(400).json({ error: "CID value is missing. Please provide the CID value as the second argument." });
    }

    try {
      const hashList = [inputCid];
      const allHashList = await downloadFileAndExtractHashes(inputCid);
      hashList.push(...allHashList);

      const blockedLinks = [];

      for (let index = 0; index < hashList.length; index++) {
        const cid = hashList[index];
        const isLinkBlocked = await checkLinkStatusAndContent(cid);
        if (isLinkBlocked) {
          blockedLinks.push(displayProcessedOutput(cid, index + 1));
        }
      }

      return res.json({ "List of blocked IPFS links:": blockedLinks, totalBlocked: blockedLinks.length });
    } catch (error) {
      return res.status(500).json({ error: "Error while fetching the list of CIDs:", details: error });
    }
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
