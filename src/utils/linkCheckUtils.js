import fetch from "node-fetch";

// Function to check if a link is blocked
export async function checkLinkStatusAndContent(cid) {
  const link = `https://ipfs.io/ipfs/${cid}`
  try {
    const response = await fetch(link);
    if (response.status === 410) {
      //console.log(`Link is blocked (410 status code): ${link}`);
      return true;
    }

    const responseText = await response.text();
    if (responseText.includes("The content that you requested has been blocked because of legal, abuse, malware or security reasons.")) {
      //console.log(`Link is blocked (error message): ${link}`);
      return true;
    }

    //console.log(`Link is not blocked: ${link}`);
    return false;
  } catch (error) {
    console.error(`Error while checking the link ${link}:`, error.message);
    return false;
  }
}
