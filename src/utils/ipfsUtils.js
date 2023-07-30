import fetch from "node-fetch";

// Function to download a file from IPFS and extract hashes
export async function downloadFileAndExtractHashes(CID, hashList = []) {
  const baseURL = 'https://gateway.lighthouse.storage/ipfs/';
  const url = `${baseURL}${CID}?format=dag-json`;

  try {
    const response = await fetch(url);

    if (response.ok) {
      const fileContent = await response.text();
      const parsedContent = JSON.parse(fileContent);
      const linkedHashes = parsedContent.Links.map(link => link.Hash['/']);
      hashList.push(...linkedHashes);

      for (const hash of linkedHashes) {
        await downloadFileAndExtractHashes(hash, hashList);
      }
    } else {
      console.warn(`Warning: Unable to fetch DAG-JSON for CID '${CID}' from IPFS. Response status: ${response.status}`);
      // You might want to consider throwing an error here if needed.
    }

    return hashList;
  } catch (error) {
    console.error('Error while downloading or processing the file:', error);
    // You can handle the error accordingly, for example, return an empty hashList or rethrow the error.
    return hashList;
  }
}
