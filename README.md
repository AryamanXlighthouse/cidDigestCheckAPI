# CID Processing System

The CID Processing API is a web-based application that allows you to process and interact with Content Identifiers (CIDs) using the IPFS and Multiformats libraries. The API provides three main functionalities:


1. **Digest Processing:** The system processes a provided CID and displays its processed output along with the list of all CIDs extracted from the content.

2. **List of CIDs:** The system fetches and displays the list of all CIDs extracted from the content.

3. **Check IPFS Link Status:** The system checks the block status of IPFS links associated with a provided CID and displays the details of blocked links along with the total number of blocked links found.

## Prerequisites

- Node.js installed on your machine.

## Installation

1. Clone the repository to your local machine:
    ```bash
    git clone https://github.com/AryamanXlighthouse/cidv1MultibaseDigest.git
    ```
2. Install the dependencies using npm:
    ```bash
    npm install
    ```
3. Create a `.env` file in the root directory of the project. Inside this file, add your `AUTH_KEY` and `PORT` (if not 3000) as follows:
```makefile
AUTH_KEY=your_auth_key
PORT=your_port_number
```




## Usage

To use the CID Processing API, you need to start the server. Run the following command in the terminal:

```bash
npm start
```

This will start the server on the default port 3000 or on the port specified in the environment variable `PORT`.

### API Endpoints

#### POST /processCID

This endpoint requires a JSON body with the following properties:

- `option`: The type of operation you want to perform. It can be one of these values: "digest", "list", or "checklink".
- `inputCid`: The CID value that you want to process.

The server will respond with a JSON object containing the result of the operation. See the examples below for more details.

### Examples

To send a request to the server, you can use tools such as curl, Postman, or any programming language with HTTP capabilities. Here are examples using curl:

1. Digest Processing

* Request:

    ```bash
    curl -H "Content-Type: application/json" -H "Authorization: Bearer <YOUR_AUTH_KEY>" -X POST -d '{"option":"digest", "inputCid":"<CID_VALUE>"}' http://localhost:3000/processCID
    ```

    * Expected Response:
    ```bash
        {
    "List of hash digest": [
        "CID 1: DIGEST BASE32 MULTIBASE: CIQNTKI4DVU3ZM2UN2IVUSQNIA5U2TAVZN2K4QF225IDOURIWRKTFMA",
        ...
    ]
    }
    ```

2. List of CIDs
* Request:

    ```bash
    curl -H "Content-Type: application/json" -H "Authorization: Bearer <YOUR_AUTH_KEY>" -X POST -d '{"option":"list", "inputCid":"<CID_VALUE>"}' http://localhost:3000/processCID
    ```

* Expected Response:
    ```bash
    {
    "List of hashes": [
        "CID 1: QmczJjxnWQJfn...",
        ...
    ]
    }
    ```

3. Check Status of Link on IPFS
* Request:

    ```bash
    curl -H "Content-Type: application/json" -H "Authorization: Bearer <YOUR_AUTH_KEY>" -X POST -d '{"option":"checklink", "inputCid":"<CID_VALUE>"}' http://localhost:3000/processCID
    ```

* Expected Response:
    ```bash
    {
  "List of blocked IPFS links": [
    "CID 1: DIGEST BASE32 MULTIBASE: CIQNTKI4DVU3ZM2UN2IVUSQNIA5U2TAVZN2K4QF225IDOURIWRKTFMA",
    ...
  ],
  "totalBlocked": 1
    }
    ```
Replace <YOUR_AUTH_KEY> with the actual authorization key you set in your .env file, and <CID_VALUE> with the CID you want to process.


## Custom Utils and IPFS Utils

The CID Processing System uses custom utility functions provided in `customUtils.js` for CID processing and functions provided in `ipfsUtils.js` to interact with IPFS and extract CIDs from content.
