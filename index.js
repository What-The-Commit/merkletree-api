import express from 'express';
import http from 'http';
import https from 'https';
import filesystem from 'fs';
import env from 'dotenv';
import awaitjs from '@awaitjs/express';
import apicache from 'apicache'
import crypto from 'crypto';
import compression from "compression";
import {MerkleTree} from "merkletreejs";
import {solidityKeccak256} from "ethers/lib/utils.js";
import keccak256 from "keccak256";
import cors from "cors";

env.config();

const privateKey = filesystem.readFileSync(process.env.SSL_PRIVATE_KEY);
const certificate = filesystem.readFileSync(process.env.SSL_CERT);

const credentials = {key: privateKey, cert: certificate};

const app = awaitjs.addAsync(express());

app.use(cors({
    origin: '*'
}));

apicache.options({
    headerBlacklist:  ['access-control-allow-origin'],
    appendKey: function(request, response) {
        return crypto.createHash('sha256').update(JSON.stringify(request.body)).digest('hex');
    }
});

const cache = apicache.middleware;
const onlyStatus200 = (req, res) => res.statusCode === 200;

app.use(express.json());

const shouldCompress = (req, res) => {
    if (req.headers['x-no-compression']) {
        // don't compress responses if this request header is present
        return false;
    }

    // fallback to standard compression
    return compression.filter(req, res);
};

app.use(compression({
    // filter decides if the response should be compressed or not,
    // based on the `shouldCompress` function above
    filter: shouldCompress,
    // threshold is the byte threshold for the response body size
    // before compression is considered, the default is 1kb
    threshold: 0
}));

// https redirect
app.use(function (request, response, next) {
    if (!request.secure) {
        return response.redirect("https://" + request.headers.host.replace(process.env.HTTP_PORT, process.env.HTTPS_PORT) + request.url);
    }

    next();
});

app.getAsync('/:address/amount', cache('24 hours', onlyStatus200), async function (request, response, next) {
    const address = request.params['address'];
    let amount = 0;

    const merkleTreeFiles = process.env.MERKLETREE_FILES.split(' ');

    for (const merkleTreeFile of merkleTreeFiles) {
        const data = filesystem.readFileSync('merkletrees/' + merkleTreeFile);
        const json = JSON.parse(data.toString());

        for (const allowlist of json) {
            if (allowlist.address === address && allowlist.amount > amount) {
                amount = allowlist.amount;
            }
        }
    }

    response.send(amount.toString());
});

app.getAsync('/signature/:address/:amount', cache('24 hours', onlyStatus200), async function (request, response, next) {
    const address = request.params['address'];
    const amount = request.params['amount'];

    const merkleTreeFiles = process.env.MERKLETREE_FILES.split(' ');
    const merkleTrees = [];

    for (const merkleTreeFile of merkleTreeFiles) {
        const data = filesystem.readFileSync('merkletrees/' + merkleTreeFile);
        const json = JSON.parse(data.toString());

        const leafNodes = json.map(function (allowlist) {
            return Buffer.from(
                // Hash in appropriate Merkle format
                solidityKeccak256(["address", "uint256"], [allowlist.address, allowlist.amount]).slice(2),
                "hex"
            );
        });

        const merkleTree = new MerkleTree(leafNodes, keccak256, { sortPairs: true });

        merkleTrees.push(merkleTree);
    }

    for (const merkleTree of merkleTrees) {
        const leaf = Buffer.from(
            // Hash in appropriate Merkle format
            solidityKeccak256(["address", "uint256"], [address, amount]).slice(2),
            "hex"
        );

        const hexProof = merkleTree.getHexProof(leaf);

        if (hexProof.length !== 0) {
            response.send(hexProof);
            break;
        }
    }

    response.status(404);
    response.send('Address not found');
});

// Because of `getAsync()`, this error handling middleware will run.
// `addAsync()` also enables async error handling middleware.
app.use(function (error, req, res, next) {
    res.send(error.message);
});

const httpServer = http.createServer(app);
const httpsServer = https.createServer(credentials, app);

httpServer.listen(process.env.HTTP_PORT);
httpsServer.listen(process.env.HTTPS_PORT);