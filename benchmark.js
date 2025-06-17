const path = require('path');
const fs = require('node:fs/promises');
const HyperledgerFabric = require('./mockHyperledgerFabric');
const { TextEncoder } = require('node:util');
const { split } = require('shamir');
const crypto = require('crypto');
const { performance } = require('perf_hooks');
const { createObjectCsvStringifier } = require('csv-writer');
// Configuration
const CHANNEL_NAME = 'sipfs';
const CHAINCODE_NAME = 'basic';
const USERNAME = 'test';
const DELAY_MS = 100;

// Utility functions
function generateRandomAccessKey(length = 16) {
    return crypto.randomBytes(length).toString('hex');
}

function hashKeyValuePairs(policyAttributes) {
    const hashedAttributes = [];
    for (const attribute of policyAttributes) {
        for (const key in attribute) {
            if (Object.hasOwnProperty.call(attribute, key)) {
                const value = attribute[key];
                const concatenated = `${key}:${JSON.stringify(value)}`;
                const combinedHash = crypto.createHash('sha256').update(concatenated).digest('hex');
                hashedAttributes.push({ [key]: value, hash: combinedHash });
            }
        }
    }
    return hashedAttributes;
}




async function saveResultsToCsv(results, benchmarkName, iterations) {
    let headers = [];
    let records = [];

    if (benchmarkName === 'create_asset') {
        // Unchanged
        headers = [
            { id: 'runs', title: 'Runs' },
            { id: 'avgLatency', title: 'Average Latency (ms)' },
            { id: 'successfulRuns', title: 'Successful Runs' },
            { id: 'totalRuns', title: 'Total Runs' }
        ];
        records = [{
            runs: results.results.runs,
            avgLatency: results.results.avgLatency,
            successfulRuns: results.results.successfulRuns,
            totalRuns: results.results.totalRuns
        }];
    } else if (benchmarkName === 'api_and_query') {
        // New case for combined API and query results
        // API Calls
        const apiHeaders = [
            { id: 'type', title: 'Type' },
            { id: 'function', title: 'Function' },
            { id: 'avgLatency', title: 'Average Latency (ms)' },
            { id: 'successfulRuns', title: 'Successful Runs' },
            { id: 'totalRuns', title: 'Total Runs' }
        ];
        const apiRecords = results.results.apiCalls.map(r => ({
            type: 'API Call',
            function: r.function,
            avgLatency: r.avgLatency,
            successfulRuns: r.successfulRuns,
            totalRuns: r.totalRuns
        }));

        // Query Latency
        const queryHeaders = [
            { id: 'type', title: 'Type' },
            { id: 'concurrency', title: 'Concurrency' },
            { id: 'readAssetAvgLatency', title: 'Read Asset Avg Latency (ms)' },
            { id: 'readAssetTPS', title: 'Read Asset TPS' },
            { id: 'getAssetsByOwnerAndNameAvgLatency', title: 'Get Assets Avg Latency (ms)' },
            { id: 'getAssetsByOwnerAndNameTPS', title: 'Get Assets TPS' }
        ];
        const queryRecords = results.results.queryLatency.map(r => ({
            type: 'Query Latency',
            concurrency: r.concurrency,
            readAssetAvgLatency: r.readAssetAvgLatency,
            readAssetTPS: r.readAssetTPS,
            getAssetsByOwnerAndNameAvgLatency: r.getAssetsByOwnerAndNameAvgLatency,
            getAssetsByOwnerAndNameTPS: r.getAssetsByOwnerAndNameTPS
        }));

        // Combine headers and records
        headers = [
            { id: 'type', title: 'Type' },
            { id: 'functionOrConcurrency', title: 'Function/Concurrency' },
            { id: 'avgLatency', title: 'Average Latency (ms)' },
            { id: 'successfulRunsOrTPS', title: 'Successful Runs/TPS' },
            { id: 'totalRunsOrMetric', title: 'Total Runs/Metric' }
        ];
        records = [
            ...results.results.apiCalls.map(r => ({
                type: 'API Call',
                functionOrConcurrency: r.function,
                avgLatency: r.avgLatency,
                successfulRunsOrTPS: r.successfulRuns,
                totalRunsOrMetric: r.totalRuns
            })),
            ...results.results.queryLatency.map(r => ({
                type: 'Query Latency',
                functionOrConcurrency: r.concurrency,
                avgLatency: r.readAssetAvgLatency,
                successfulRunsOrTPS: r.readAssetTPS,
                totalRunsOrMetric: 'ReadAsset'
            })),
            ...results.results.queryLatency.map(r => ({
                type: 'Query Latency',
                functionOrConcurrency: r.concurrency,
                avgLatency: r.getAssetsByOwnerAndNameAvgLatency,
                successfulRunsOrTPS: r.getAssetsByOwnerAndNameTPS,
                totalRunsOrMetric: 'GetAssetsByOwnerAndName'
            }))
        ];
    } else if (benchmarkName === 'promotion_check_by_attribute_count') {
        // Unchanged
        headers = [
            { id: 'attributeCount', title: 'Attribute Count' },
            { id: 'avgLatency', title: 'Average Latency (ms)' },
            { id: 'successfulRuns', title: 'Successful Runs' },
            { id: 'totalRuns', title: 'Total Runs' },
            { id: 'accessGrantedCount', title: 'Access Granted Count' },
            { id: 'accessGrantedRate', title: 'Access Achievements' }
        ];
        records = results.results.map(r => ({
            attributeCount: r.attributeCount,
            avgLatency: r.avgLatency,
            successfulRuns: r.successfulRuns,
            totalRuns: r.totalRuns,
            accessGrantedCount: r.accessGrantedCount,
            accessGrantedRate: r.accessGrantedRate
        }));
    } else if (benchmarkName === 'promote_api') {
        // Unchanged (updated from promote_demote to promote_api)
        headers = [
            { id: 'function', title: 'Function' },
            { id: 'description', title: 'Description' },
            { id: 'avgLatency', title: 'Average Latency (ms)' },
            { id: 'successfulRuns', title: 'Successful Runs' },
            { id: 'totalRuns', title: 'Total Runs' }
        ];
        records = results.results.map(r => ({
            function: r.function,
            description: r.description || '',
            avgLatency: r.avgLatency,
            successfulRuns: r.successfulRuns,
            totalRuns: r.totalRuns
        }));
    } else if (benchmarkName === 'least_privilege') {
        // Unchanged
        headers = [
            { id: 'test', title: 'Test' },
            { id: 'status', title: 'Status' },
            { id: 'description', title: 'Description' },
            { id: 'error', title: 'Error' }
        ];
        records = results.map(r => ({
            test: r.test,
            status: r.status,
            description: r.description,
            error: r.error || ''
        }));
    }

    if (headers.length === 0 || records.length === 0) {
        console.error(`No data to write to CSV for ${benchmarkName}`);
        return;
    }

    const csvWriter = createObjectCsvStringifier({
        header: headers
    });
    const csvContent = csvWriter.getHeaderString() + csvWriter.stringifyRecords(records);
    const outputFile = path.join(__dirname, `${benchmarkName}_avg_${iterations || 'test'}.csv`);
    await fs.writeFile(outputFile, csvContent);
    console.log(`Saved CSV results for ${benchmarkName} to ${outputFile}`);
}


async function runBenchmarkWithIterations(benchmarkFn, iterationCounts, benchmarkName) {
    const allResults = {};

    for (const iterations of iterationCounts) {
        console.log(`Running ${benchmarkName} for ${iterations} iterations...`);
        const iterationResults = [];
        let failedRuns = 0;

        for (let i = 0; i < iterations; i++) {
            try {
                console.log(`Iteration ${i + 1}/${iterations}`);
                const result = await benchmarkFn();
                iterationResults.push(result);
            } catch (error) {
                console.error(`Error in ${benchmarkName} iteration ${i + 1}:`, error.message);
                failedRuns++;
            }
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        // Compute averages
        const averagedResult = aggregateResults(iterationResults, iterations, failedRuns);
        allResults[`${iterations}_iterations`] = averagedResult;

        // Save intermediate results as JSON
        const outputFile = path.join(__dirname, `${benchmarkName}_avg_${iterations}.json`);
        await fs.writeFile(outputFile, JSON.stringify(averagedResult, null, 2));
        console.log(`Saved JSON results for ${iterations} iterations to ${outputFile}`);

        // Save intermediate results as CSV
        await saveResultsToCsv(averagedResult, benchmarkName, iterations);
    }

    // Save combined results as JSON
    const combinedOutputFile = path.join(__dirname, `${benchmarkName}_avg_all.json`);
    await fs.writeFile(combinedOutputFile, JSON.stringify(allResults, null, 2));
    console.log(`Saved combined JSON results to ${combinedOutputFile}`);

    // Save combined results as CSV (for each iteration count)
    for (const iterations in allResults) {
        await saveResultsToCsv(allResults[iterations], benchmarkName, iterations.replace('_iterations', ''));
    }

    return allResults;
}


function aggregateResults(results, totalIterations, failedRuns) {
    if (results.length === 0) {
        return {
            iterations: totalIterations,
            successfulIterations: 0,
            failedIterations: failedRuns,
            results: { apiCalls: [], queryLatency: [] }
        };
    }

    // Handle benchmarkCreateAsset (single object)
    if (!Array.isArray(results[0])) {
        const validResults = results.filter(r => r.avgLatency >= 0);
        const successfulRuns = validResults.reduce((sum, r) => sum + r.successfulRuns, 0) / validResults.length || 0;
        const totalRuns = validResults.reduce((sum, r) => sum + r.totalRuns, 0) / validResults.length || 0;
        const avgLatency = validResults.reduce((sum, r) => sum + (parseFloat(r.avgLatency) || 0), 0) / validResults.length || -1;

        return {
            iterations: totalIterations,
            successfulIterations: validResults.length,
            failedIterations: failedRuns,
            results: {
                avgLatency: avgLatency >= 0 ? avgLatency.toFixed(3) : -1,
                latencyUnit: 'milliseconds',
                successfulRuns: Math.round(successfulRuns),
                totalRuns: Math.round(totalRuns)
            }
        };
    }

    // Handle benchmarkApiAndQuery (combined API calls and query latency)
    const isApiAndQuery = results[0].apiCalls && results[0].queryLatency;
    if (isApiAndQuery) {
        // Aggregate API Calls
        const apiAggregated = results[0].apiCalls.map(template => {
            const functionResults = results
                .filter(r => r.apiCalls.find(item => item.function === template.function))
                .map(r => r.apiCalls.find(item => item.function === template.function));

            const successfulRuns = functionResults.reduce((sum, r) => sum + r.successfulRuns, 0) / functionResults.length;
            const totalRuns = functionResults.reduce((sum, r) => sum + r.totalRuns, 0) / functionResults.length;
            const avgLatency = functionResults.reduce((sum, r) => sum + (parseFloat(r.avgLatency) || 0), 0) / functionResults.length;

            return {
                ...template,
                avgLatency: avgLatency >= 0 ? avgLatency.toFixed(3) : -1,
                successfulRuns: Math.round(successfulRuns),
                totalRuns: Math.round(totalRuns)
            };
        });

        // Aggregate Query Latency
        const queryAggregated = results[0].queryLatency.map(template => {
            const functionResults = results
                .filter(r => r.queryLatency.find(item => item.concurrency === template.concurrency))
                .map(r => r.queryLatency.find(item => item.concurrency === template.concurrency));

            const readAvgLatency = functionResults.reduce((sum, r) => sum + (parseFloat(r.readAssetAvgLatency) || 0), 0) / functionResults.length;
            const readTPS = functionResults.reduce((sum, r) => sum + (parseFloat(r.readAssetTPS) || 0), 0) / functionResults.length;
            const assetsAvgLatency = functionResults.reduce((sum, r) => sum + (parseFloat(r.getAssetsByOwnerAndNameAvgLatency) || 0), 0) / functionResults.length;
            const assetsTPS = functionResults.reduce((sum, r) => sum + (parseFloat(r.getAssetsByOwnerAndNameTPS) || 0), 0) / functionResults.length;

            return {
                ...template,
                readAssetAvgLatency: readAvgLatency >= 0 ? readAvgLatency.toFixed(3) : -1,
                readAssetTPS: readTPS >= 0 ? readTPS.toFixed(2) : -1,
                getAssetsByOwnerAndNameAvgLatency: assetsAvgLatency >= 0 ? assetsAvgLatency.toFixed(3) : -1,
                getAssetsByOwnerAndNameTPS: assetsTPS >= 0 ? assetsTPS.toFixed(2) : -1
            };
        });

        return {
            iterations: totalIterations,
            successfulIterations: results.length,
            failedIterations: failedRuns,
            results: {
                apiCalls: apiAggregated,
                queryLatency: queryAggregated
            }
        };
    }

    // Handle benchmarkPromotionCheckByAttributeCount (attributeCount-based)
    const isPromotionCheck = results[0][0] && 'attributeCount' in results[0][0];
    if (isPromotionCheck) {
        const aggregated = results[0].map(template => {
            const functionResults = results
                .filter(r => r.find(item => item.attributeCount === template.attributeCount))
                .map(r => r.find(item => item.attributeCount === template.attributeCount));

            const successfulRuns = functionResults.reduce((sum, r) => sum + r.successfulRuns, 0) / functionResults.length;
            const totalRuns = functionResults.reduce((sum, r) => sum + r.totalRuns, 0) / functionResults.length;
            const avgLatency = functionResults.reduce((sum, r) => sum + (parseFloat(r.avgLatency) || 0), 0) / functionResults.length;
            const accessGrantedCount = functionResults.reduce((sum, r) => sum + r.accessGrantedCount, 0) / functionResults.length;
            const accessGrantedRate = functionResults.reduce((sum, r) => sum + (r.accessGrantedCount / r.successfulRuns || 0), 0) / functionResults.length;

            return {
                ...template,
                avgLatency: avgLatency >= 0 ? avgLatency.toFixed(3) : -1,
                successfulRuns: Math.round(successfulRuns),
                totalRuns: Math.round(totalRuns),
                accessGrantedCount: Math.round(accessGrantedCount),
                accessGrantedRate: accessGrantedRate.toFixed(3)
            };
        });

        return {
            iterations: totalIterations,
            successfulIterations: results.length,
            failedIterations: failedRuns,
            results: aggregated
        };
    }

    // Handle benchmarkPromoteDemote (function-based)
    const aggregated = results[0].map(template => {
        const functionResults = results
            .filter(r => r.find(item => item.function === template.function))
            .map(r => r.find(item => item.function === template.function));

        const successfulRuns = functionResults.reduce((sum, r) => sum + r.successfulRuns, 0) / functionResults.length;
        const totalRuns = functionResults.reduce((sum, r) => sum + r.totalRuns, 0) / functionResults.length;
        const avgLatency = functionResults.reduce((sum, r) => sum + (parseFloat(r.avgLatency) || 0), 0) / functionResults.length;

        return {
            ...template,
            avgLatency: avgLatency >= 0 ? avgLatency.toFixed(3) : -1,
            successfulRuns: Math.round(successfulRuns),
            totalRuns: Math.round(totalRuns)
        };
    });

    return {
        iterations: totalIterations,
        successfulIterations: results.length,
        failedIterations: failedRuns,
        results: aggregated
    };
}
function encrypt(text, symmetricKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(symmetricKey), iv);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText, symmetricKey) {
    const textParts = encryptedText.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedData = textParts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(symmetricKey), iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}

function generateUniqueId(prefix) {
    return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

// Attribute pools for random generation
const ATTRIBUTE_POOLS = {
    department: ['engineering', 'finance', 'hr', 'marketing', 'sales', 'it', 'research', 'operations', 'legal', 'support', 'qa', 'product', 'logistics', 'training', 'compliance'],
    role: ['developer', 'manager', 'analyst', 'designer', 'engineer', 'consultant', 'admin', 'director', 'specialist', 'coordinator', 'architect', 'tester', 'scientist', 'executive', 'trainer'],
    location: ['us', 'eu', 'asia', 'africa', 'australia', 'south_america', 'canada', 'middle_east', 'india', 'japan', 'china', 'brazil', 'uk', 'germany', 'france'],
    skills: ['python', 'java', 'sql', 'javascript', 'cloud', 'devops', 'ai', 'blockchain', 'cybersecurity', 'data_analysis', 'ml', 'networking', 'ui_ux', 'big_data', 'embedded'],
    clearance: ['public', 'confidential', 'secret', 'top_secret', 'restricted', 'classified', 'sensitive', 'internal', 'external', 'executive'],
    languages: ['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko', 'ar', 'hi', 'bn', 'sw', 'nl'],
    interest: ['tech', 'finance', 'health', 'education', 'sports', 'music', 'art', 'science', 'travel', 'gaming', 'environment', 'politics', 'fashion', 'food', 'literature']
};

function getRandomSubset(array, n) {
    const shuffled = array.sort(() => 0.5 - Math.random());
    return shuffled.slice(0, Math.min(n, array.length));
}

function generateRandomPolicyAttribute() {
    const numKeys = Math.floor(Math.random() * 3) + 5;
    const availableKeys = Object.keys(ATTRIBUTE_POOLS);
    const selectedKeys = getRandomSubset(availableKeys, numKeys);
    const attribute = {};
    
    selectedKeys.forEach(key => {
        const numValues = Math.floor(Math.random() * 6) + 5;
        attribute[key] = getRandomSubset(ATTRIBUTE_POOLS[key], numValues);
    });
    
    return attribute;
}

function generateUserPolicySet(attributeCount, includeRequired = false, requiredPolicies = []) {
    const attributes = [];
    const requiredPolicyOptions = requiredPolicies.length > 0 ? requiredPolicies : [
        {
            department: ['engineering'],
            role: ['developer'],
            skills: ['python'],
            clearance: ['confidential'],
            location: ['us'],
            languages: ['en'],
            interest: ['tech']
        }
    ];
    
    if (includeRequired && requiredPolicyOptions.length > 0) {
        const randomIndex = Math.floor(Math.random() * requiredPolicyOptions.length);
        attributes.push(requiredPolicyOptions[randomIndex]);
    }
    
    for (let i = attributes.length; i < attributeCount; i++) {
        attributes.push(generateRandomPolicyAttribute());
    }
    
    return JSON.stringify(attributes.sort(() => 0.5 - Math.random()));
}

function generateShamirFragments(secret, parts, quorum) {
    const utf8Encoder = new TextEncoder();
    const secretBytes = utf8Encoder.encode(secret);
    const shares = split(crypto.randomBytes, parts, quorum, secretBytes);

    const policyAttributes = Array.from({ length: parts }, (_, i) => ({
        interest: [`topic${i + 1}`],
        languages: ['en'],
    }));

    const hashedAttributes = hashKeyValuePairs(policyAttributes);

    const fragmentsMap = hashedAttributes.slice(0, parts).map((attr, index) => ({
        ...attr,
        share: shares[index + 1],
    }));

    return { fragmentsMap, hashedAttributes };
}

async function connectToUserGateway(username, userType) {
    const fabric = new HyperledgerFabric();
    return await fabric.connectToGateway(username, userType);
}

async function setupTestData(contract) {
    console.log('Setting up test data for benchmarks...');
    const assetId = generateUniqueId('asset');
    const userId = generateUniqueId('user');
    const currentDate = new Date().toISOString();

    try {
        // Reset mock state to avoid stale data
        contract.stub.resetState();
        console.log(`Mock state reset for asset ${assetId} and user ${userId}`);

        // Ensure the owner user exists
        let ownerExists = false;
        try {
            const ownerExistsResult = await contract.evaluateTransaction('UserExists', USERNAME);
            if (ownerExistsResult && ownerExistsResult.length > 0) {
                ownerExists = JSON.parse(ownerExistsResult.toString());
                console.log(`Owner user ${USERNAME} exists: ${ownerExists}`);
                if (ownerExists) {
                    const ownerResult = await contract.evaluateTransaction('GetUser', USERNAME);
                    if (!ownerResult || ownerResult.length === 0) {
                        console.log(`Owner user ${USERNAME} exists but has invalid state, recreating...`);
                        ownerExists = false;
                    }
                }
            }
        } catch (error) {
            console.log(`Owner user ${USERNAME} does not exist, will create: ${error.message}`);
            ownerExists = false;
        }
        if (!ownerExists) {
            const policySet = generateUserPolicySet(1, true);
            await contract.submitTransaction(
                'CreateUser',
                USERNAME,
                'owner',
                currentDate,
                'dummy-public-key',
                policySet
            );
            console.log(`Owner user ${USERNAME} created successfully`);
        } else {
            console.log(`Owner user ${USERNAME} already exists, skipping creation`);
        }

        // Create test user with policy matching asset's promoteAttributes
        let userExists = false;
        try {
            const userExistsResult = await contract.evaluateTransaction('UserExists', userId);
            if (userExistsResult && userExistsResult.length > 0) {
                userExists = JSON.parse(userExistsResult.toString());
                console.log(`User ${userId} exists: ${userExists}`);
                if (userExists) {
                    const userResult = await contract.evaluateTransaction('GetUser', userId);
                    if (!userResult || userResult.length === 0) {
                        console.log(`User ${userId} exists but has invalid state, recreating...`);
                        userExists = false;
                    }
                }
            }
        } catch (error) {
            console.log(`User ${userId} does not exist, will create: ${error.message}`);
            userExists = false;
        }
        if (!userExists) {
            const policySet = generateUserPolicySet(1, true, [{
                interest: ['tech'],
                languages: ['en']
            }]);
            await contract.submitTransaction(
                'CreateUser',
                userId,
                'requester',
                currentDate,
                'dummy-public-key',
                policySet
            );
            console.log(`User ${userId} created successfully with matching policy`);
        } else {
            console.log(`User ${userId} already exists, skipping creation`);
        }

        // Create test asset
        let assetExists = false;
        try {
            const assetExistsResult = await contract.evaluateTransaction('AssetExists', assetId);
            if (assetExistsResult && assetExistsResult.length > 0) {
                assetExists = JSON.parse(assetExistsResult.toString());
            }
        } catch (error) {
            console.error(`Error checking if asset ${assetId} exists:`, error.message);
            assetExists = false;
        }
        if (assetExists) {
            console.log(`Asset ${assetId} already exists, deleting...`);
            try {
                await contract.submitTransaction('DeleteAsset', assetId);
                console.log(`Asset ${assetId} deleted successfully`);
            } catch (error) {
                console.error(`Error deleting asset ${assetId}:`, error.message);
            }
        }

        const metaData = JSON.stringify({ description: 'Test asset for promotion' });
        const policySet = JSON.stringify([
            {
                interest: ['tech'],
                languages: ['en']
            }
        ]);
        const promoteAttributes = JSON.stringify([
            {
                interest: ['tech'],
                languages: ['en']
            }
        ]);
        const publicKeyOwner = 'pubkey123';
        const name = 'TestAsset';
        const cid = 'cid123';
        const prevCid = '';
        const key = generateRandomAccessKey();
        const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
        const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

        await contract.submitTransaction(
            'CreateAsset',
            assetId,
            metaData,
            policySet,
            publicKeyOwner,
            currentDate,
            currentDate,
            USERNAME,
            name,
            cid,
            prevCid,
            hashAccessKey,
            JSON.stringify(fragmentsMap),
            JSON.stringify(hashedAttributes),
            promoteAttributes
        );
        console.log(`Asset ${assetId} created successfully`);

        return { userId, assetId, owner: USERNAME };
    } catch (error) {
        console.error('Error in setupTestData:', error.message);
        throw error;
    }
}

async function cleanupTestData(contract, assetId, userId) {
    try {
        if (assetId && contract) {
            let existsResult;
            try {
                existsResult = await contract.evaluateTransaction('AssetExists', assetId);
            } catch (error) {
                console.error(`Error checking if asset ${assetId} exists during cleanup:`, error.message);
                existsResult = false;
            }
            if (existsResult && JSON.parse(existsResult.toString())) {
                await contract.submitTransaction('DeleteAsset', assetId);
                console.log(`Successfully deleted asset ${assetId}`);
            } else {
                console.log(`Asset ${assetId} does not exist, skipping deletion`);
            }
        }
        if (userId && contract) {
            let existsResult;
            try {
                existsResult = await contract.evaluateTransaction('UserExists', userId);
            } catch (error) {
                console.error(`Error checking if user ${userId} exists during cleanup:`, error.message);
                existsResult = false;
            }
            if (existsResult && JSON.parse(existsResult.toString())) {
                await contract.submitTransaction('DeleteUser', userId);
                console.log(`Successfully deleted user ${userId}`);
            } else {
                console.log(`User ${userId} does not exist, skipping deletion`);
            }
        }
    } catch (e) {
        console.error(`Cleanup failed for asset ${assetId} or user ${userId}:`, e.message);
    }
}

async function cleanupAssetsBatch(contract, assetIds) {
    const batchSize = 5;
    for (let i = 0; i < assetIds.length; i += batchSize) {
        const batch = assetIds.slice(i, i + batchSize);
        const promises = batch.map((assetId) => cleanupTestData(contract, assetId, null));
        await Promise.all(promises);
        console.log(`Completed cleanup batch ${i / batchSize + 1}/${Math.ceil(assetIds.length / batchSize)}`);
        await new Promise((resolve) => setTimeout(resolve, DELAY_MS));
    }
}

function hybridEncrypt(fragment, publicKey) {
    const plaintext = typeof fragment === 'string'
        ? Buffer.from(fragment, 'utf8')
        : Buffer.from(JSON.stringify(fragment), 'utf8');

    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const wrappedKey = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        aesKey
    );

    return {
        encryptedData: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        wrappedKey: wrappedKey.toString('base64'),
    };
}
async function measureFunction(contract, functionName, args, isQuery) {
    const startTime = performance.now();
    try {
        if (args.some(arg => arg === null || arg === undefined)) {
            console.error(`Invalid arguments for ${functionName}: ${JSON.stringify(args)}`);
            return { duration: -1, result: null };
        }

        if (functionName === 'CreateUser') {
            let existsResult;
            try {
                existsResult = await contract.evaluateTransaction('UserExists', args[0]);
                if (existsResult && JSON.parse(existsResult.toString())) {
                    console.log(`User ${args[0]} already exists, deleting and recreating...`);
                    await contract.submitTransaction('DeleteUser', args[0]);
                }
            } catch (error) {
                console.error(`Error checking if user ${args[0]} exists:`, error.message);
            }
        } else if (functionName === 'CreateAsset' || functionName === 'UpdateAsset') {
            let existsResult;
            try {
                existsResult = await contract.evaluateTransaction('AssetExists', args[0]);
                if (functionName === 'CreateAsset' && existsResult && JSON.parse(existsResult.toString())) {
                    console.log(`Asset ${args[0]} already exists, deleting and recreating...`);
                    await contract.submitTransaction('DeleteAsset', args[0]);
                }
                if (functionName === 'UpdateAsset' && (!existsResult || !JSON.parse(existsResult.toString()))) {
                    console.log(`Asset ${args[0]} does not exist, skipping update`);
                    return { duration: -1, result: null };
                }
            } catch (error) {
                console.error(`Error checking if asset ${args[0]} exists:`, error.message);
                return { duration: -1, result: null };
            }

            const key = generateRandomAccessKey();
            const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
            const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

            const worker1Path = path.resolve(__dirname, './workers/w1-keys.json');
            const worker2Path = path.resolve(__dirname, './workers/w2-keys.json');
            let w1Keys, w2Keys;
            try {
                const w1Data = await fs.readFile(worker1Path, 'utf8');
                const w2Data = await fs.readFile(worker2Path, 'utf8');
                w1Keys = JSON.parse(w1Data);
                w2Keys = JSON.parse(w2Data);
            } catch (error) {
                console.error(`Error reading worker key files: ${error.message}`);
                throw error;
            }

            const encryptedFragments = {};
            for (const [idx, fragment] of Object.entries(fragmentsMap)) {
                encryptedFragments[idx] = {
                    byKey1: hybridEncrypt(fragment, w1Keys.publicKey),
                    byKey2: hybridEncrypt(fragment, w2Keys.publicKey),
                };
            }

            args[10] = hashAccessKey;
            args[11] = JSON.stringify(encryptedFragments);
            args[12] = JSON.stringify(hashedAttributes);
            args[13] = args[13] || JSON.stringify([
                {
                    interest: ['tech'],
                    languages: ['en']
                }
            ]);
        } else if (functionName === 'PromoteAccess') {
            let asset;
            try {
                const assetResult = await contract.evaluateTransaction('ReadAsset', args[1]);
                asset = assetResult ? JSON.parse(assetResult.toString()) : null;
            } catch (error) {
                console.error(`Error reading asset ${args[1]}:`, error.message);
                return { duration: -1, result: null };
            }
            if (!asset) {
                console.log(`Asset ${args[1]} not found, skipping PromoteAccess`);
                return { duration: -1, result: null };
            }
            let promotedAccess = Array.isArray(asset.promotedAccess) ? asset.promotedAccess : [];
            if (promotedAccess.some(access => access.username === args[0])) {
                console.log(`User ${args[0]} already promoted for asset ${args[1]}, skipping`);
                return { duration: -1, result: null };
            }
        } else if (functionName === 'CheckAccess') {
            try {
                const assetResult = await contract.evaluateTransaction('ReadAsset', args[1]);
                const userResult = await contract.evaluateTransaction('GetUser', args[0]);
                const asset = assetResult ? JSON.parse(assetResult.toString()) : null;
                const user = userResult ? JSON.parse(userResult.toString()) : null;
                if (!asset || !user) {
                    console.log(`Asset ${args[1]} or user ${args[0]} not found, skipping CheckAccess`);
                    return { duration: -1, result: null };
                }
            } catch (error) {
                console.error(`Error validating asset ${args[1]} or user ${args[0]} for CheckAccess:`, error.message);
                return { duration: -1, result: null };
            }
        } else if (functionName === 'RevokePermanentAccess') {
            let asset;
            try {
                const assetResult = await contract.evaluateTransaction('ReadAsset', args[1]);
                asset = assetResult ? JSON.parse(assetResult.toString()) : null;
            } catch (error) {
                console.error(`Error reading asset ${args[1]}:`, error.message);
                return { duration: -1, result: null };
            }
            if (!asset) {
                console.log(`Asset ${args[1]} not found, skipping RevokePermanentAccess`);
                return { duration: -1, result: null };
            }
            // Check if user is already revoked
            let revokedAccess = Array.isArray(asset.revokedAccess) ? asset.revokedAccess : [];
            if (revokedAccess.some(access => access.username === args[0])) {
                console.log(`User ${args[0]} already revoked for asset ${args[1]}, skipping`);
                return { duration: -1, result: null };
            }
        } else if (functionName === 'GrantAccess') {
            let asset;
            try {
                const assetResult = await contract.evaluateTransaction('ReadAsset', args[1]);
                asset = assetResult ? JSON.parse(assetResult.toString()) : null;
            } catch (error) {
                console.error(`Error reading asset ${args[1]}:`, error.message);
                return { duration: -1, result: null };
            }
            if (!asset) {
                console.log(`Asset ${args[1]} not found, skipping GrantAccess`);
                return { duration: -1, result: null };
            }
            // Check if user is already granted access
            let grantedAccess = Array.isArray(asset.grantedAccess) ? asset.grantedAccess : [];
            if (grantedAccess.some(access => access.username === args[0])) {
                console.log(`User ${args[0]} already has access to asset ${args[1]}, skipping`);
                return { duration: -1, result: null };
            }
        }

        let result;
        if (isQuery) {
            result = await contract.evaluateTransaction(functionName, ...args);
        } else {
            result = await contract.submitTransaction(functionName, ...args);
        }
        const endTime = performance.now();
        return { duration: endTime - startTime, result };
    } catch (error) {
        console.error(`Error measuring ${functionName} with args ${JSON.stringify(args)}:`, error.message);
        return { duration: -1, result: null };
    }
}


async function benchmarkApiAndQuery() {
    const results = {
        apiCalls: [],
        queryLatency: []
    };
    let gateway = null;
    let contract = null;
    let testData = null;

    try {
        console.log('Connecting to gateway for API and query benchmark...');
        gateway = await connectToUserGateway(USERNAME, 'owner');
        const network = await gateway.getNetwork(CHANNEL_NAME);
        contract = network.getContract(CHAINCODE_NAME);

        console.log('Setting up test data for API and query benchmark...');
        testData = await setupTestData(contract);
        const { userId, assetId, owner } = testData || {};
        const runs = 5;
        const concurrencyLevels = [5, 80, 200, 400, 600, 1000];

        // API Call Benchmark (from benchmarkApiCallTimes)
        const policyAttributes = [
            {
                interest: ['tech'],
                languages: ['en']
            }
        ];
        const newUserId = generateUniqueId('user');
        const newAssetId = generateUniqueId('asset');
        const currentDate = new Date().toISOString();
        const key = generateRandomAccessKey();
        const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
        const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

        const apiFunctions = [
            { name: 'UserExists', args: [userId], isQuery: true },
            { name: 'GetUser', args: [userId], isQuery: true },
            { name: 'GetAssetsByOwnerAndName', args: [owner, 'TestAsset', 'DEMO'], isQuery: true },
            { name: 'AssetExists', args: [assetId], isQuery: true },
            { name: 'ReadAsset', args: [assetId], isQuery: true },
            { name: 'CheckAccess', args: [userId, assetId], isQuery: true },
            { name: 'GetAllAssets', args: [], isQuery: true },
            {
                name: 'CreateUser',
                args: [
                    newUserId,
                    'testRole',
                    currentDate,
                    'dummy-public-key',
                    JSON.stringify(policyAttributes),
                ],
                isQuery: false,
            },
            {
                name: 'CreateAsset',
                args: [
                    newAssetId,
                    JSON.stringify({ description: 'Test asset' }),
                    JSON.stringify(policyAttributes),
                    'dummy-public-key',
                    currentDate,
                    currentDate,
                    owner,
                    'test-asset',
                    'dummy-cid',
                    '',
                    hashAccessKey,
                    JSON.stringify(fragmentsMap),
                    JSON.stringify(hashedAttributes),
                    JSON.stringify([
                        {
                            interest: ['tech'],
                            languages: ['en']
                        }
                    ]),
                ],
                isQuery: false,
            },
            {
                name: 'UpdateAsset',
                args: [
                    assetId,
                    JSON.stringify({ description: 'Updated asset' }),
                    JSON.stringify(policyAttributes),
                    'dummy-public-key',
                    currentDate,
                    currentDate,
                    owner,
                    'TestAsset',
                    'dummy-cid',
                    '',
                    hashAccessKey,
                    JSON.stringify(fragmentsMap),
                    JSON.stringify(hashedAttributes),
                    JSON.stringify([
                        {
                            interest: ['tech'],
                            languages: ['en']
                        }
                    ]),
                ],
                isQuery: false,
            },
            { name: 'RevokePermanentAccess', args: [userId, assetId, currentDate], isQuery: false },
            { name: 'GrantAccess', args: [userId, assetId, currentDate], isQuery: false },
        ];

        for (const func of apiFunctions) {
            let totalTime = 0;
            let successfulRuns = 0;

            console.log(`Benchmarking API call ${func.name}...`);
            if (func.isQuery) {
                const promises = Array.from({ length: runs }, () =>
                    measureFunction(contract, func.name, func.args, func.isQuery)
                );
                const outcomes = await Promise.all(promises);
                for (const outcome of outcomes) {
                    if (outcome.duration >= 0) {
                        totalTime += outcome.duration;
                        successfulRuns++;
                    }
                }
            } else {
                for (let i = 0; i < runs; i++) {
                    const outcome = await measureFunction(contract, func.name, func.args, func.isQuery);
                    if (outcome.duration >= 0) {
                        totalTime += outcome.duration;
                        successfulRuns++;
                    }
                    await new Promise((resolve) => setTimeout(resolve, DELAY_MS));
                }
            }

            const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;
            results.apiCalls.push({
                function: func.name,
                avgLatency,
                latencyUnit: 'milliseconds',
                successfulRuns,
                totalRuns: runs
            });
        }

        // Query Latency Benchmark (from benchmarkQueryLatency)
        for (const concurrency of concurrencyLevels) {
            console.log(`Benchmarking query latency at concurrency ${concurrency}...`);
            const readPromises = Array.from({ length: concurrency }, () =>
                measureFunction(contract, 'ReadAsset', [assetId], true)
            );
            const readStart = performance.now();
            const readOutcomes = await Promise.all(readPromises);
            const readTotalTime = (performance.now() - readStart) / 1000;
            const validReadDurations = readOutcomes.filter((o) => o.duration >= 0).map(o => o.duration);
            const readAvgLatency =
                validReadDurations.length > 0
                    ? validReadDurations.reduce((sum, latency) => sum + latency, 0) / validReadDurations.length
                    : -1;
            const readTPS = validReadDurations.length / readTotalTime;

            const assetsPromises = Array.from({ length: concurrency }, () =>
                measureFunction(contract, 'GetAssetsByOwnerAndName', [owner, 'TestAsset', 'DEMO'], true)
            );
            const assetsStart = performance.now();
            const assetsOutcomes = await Promise.all(assetsPromises);
            const assetsTotalTime = (performance.now() - assetsStart) / 1000;
            const validAssetsDurations = assetsOutcomes.filter((o) => o.duration >= 0).map(o => o.duration);
            const assetsAvgLatency =
                validAssetsDurations.length > 0
                    ? validAssetsDurations.reduce((sum, latency) => sum + latency, 0) / validAssetsDurations.length
                    : -1;
            const assetsTPS = validAssetsDurations.length / assetsTotalTime;

            results.queryLatency.push({
                concurrency,
                readAssetAvgLatency: readAvgLatency.toFixed(3),
                readAssetTPS: readTPS.toFixed(2),
                getAssetsByOwnerAndNameAvgLatency: assetsAvgLatency.toFixed(3),
                getAssetsByOwnerAndNameTPS: assetsTPS.toFixed(2)
            });
        }

        console.log('Writing API and query benchmark results to file...');
        await fs.writeFile(
            path.join(__dirname, 'api_and_query_benchmark.json'),
            JSON.stringify(results, null, 2)
        );

        return results;
    } catch (error) {
        console.error('Error in benchmarkApiAndQuery:', error.message);
        throw error;
    } finally {
        if (testData && contract) {
            console.log('Cleaning up test data for API and query benchmark...');
            await cleanupTestData(contract, testData.assetId, testData.userId);
            await cleanupTestData(contract, newAssetId, newUserId);
        }
        if (gateway) {
            console.log('Disconnecting gateway for API and query benchmark...');
            await gateway.disconnect();
        }
    }
}


async function benchmarkApiCallTimes() {
    const results = [];
    let gateway;
    try {
        gateway = await connectToUserGateway(USERNAME, 'owner');
        const network = await gateway.getNetwork(CHANNEL_NAME);
        const contract = network.getContract(CHAINCODE_NAME);

        const testData = await setupTestData(contract);
        const { userId, assetId, owner } = testData || {};
        const runs = 5;

        const policyAttributes = [
            {
                interest: ['tech'],
                languages: ['en']
            }
        ];
        const newUserId = generateUniqueId('user');
        const newAssetId = generateUniqueId('asset');
        const currentDate = new Date().toISOString();
        const key = generateRandomAccessKey();
        const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
        const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

        const functions = [
            { name: 'UserExists', args: [userId], isQuery: true },
            { name: 'GetUser', args: [userId], isQuery: true },
            { name: 'GetAssetsByOwnerAndName', args: [owner, 'TestAsset', 'DEMO'], isQuery: true },
            { name: 'AssetExists', args: [assetId], isQuery: true },
            { name: 'ReadAsset', args: [assetId], isQuery: true },
            { name: 'CheckAccess', args: [userId, assetId], isQuery: true },
            { name: 'GetAllAssets', args: [], isQuery: true },
            {
                name: 'CreateUser',
                args: [
                    newUserId,
                    'testRole',
                    currentDate,
                    'dummy-public-key',
                    JSON.stringify(policyAttributes),
                ],
                isQuery: false,
            },
            {
                name: 'CreateAsset',
                args: [
                    newAssetId,
                    JSON.stringify({ description: 'Test asset' }),
                    JSON.stringify(policyAttributes),
                    'dummy-public-key',
                    currentDate,
                    currentDate,
                    owner,
                    'test-asset',
                    'dummy-cid',
                    '',
                    hashAccessKey,
                    JSON.stringify(fragmentsMap),
                    JSON.stringify(hashedAttributes),
                    JSON.stringify([
                        {
                            interest: ['tech'],
                            languages: ['en']
                        }
                    ]),
                ],
                isQuery: false,
            },
            {
                name: 'UpdateAsset',
                args: [
                    assetId,
                    JSON.stringify({ description: 'Updated asset' }),
                    JSON.stringify(policyAttributes),
                    'dummy-public-key',
                    currentDate,
                    currentDate,
                    owner,
                    'TestAsset',
                    'dummy-cid',
                    '',
                    hashAccessKey,
                    JSON.stringify(fragmentsMap),
                    JSON.stringify(hashedAttributes),
                    JSON.stringify([
                        {
                            interest: ['tech'],
                            languages: ['en']
                        }
                    ]),
                ],
                isQuery: false,
            },
            { name: 'RevokePermanentAccess', args: [userId, assetId, currentDate], isQuery: false },
            { name: 'GrantAccess', args: [userId, assetId, currentDate], isQuery: false },
        ];

        for (const func of functions) {
            let totalTime = 0;
            let successfulRuns = 0;

            console.log(`Benchmarking ${func.name}...`);
            if (func.isQuery) {
                const promises = Array.from({ length: runs }, () =>
                    measureFunction(contract, func.name, func.args, func.isQuery)
                );
                const outcomes = await Promise.all(promises);
                for (const outcome of outcomes) {
                    if (outcome.duration >= 0) {
                        totalTime += outcome.duration;
                        successfulRuns++;
                    }
                }
            } else {
                for (let i = 0; i < runs; i++) {
                    const outcome = await measureFunction(contract, func.name, func.args, func.isQuery);
                    if (outcome.duration >= 0) {
                        totalTime += outcome.duration;
                        successfulRuns++;
                    }
                    await new Promise((resolve) => setTimeout(resolve, DELAY_MS));
                }
            }

            const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;
            results.push({
                function: func.name,
                avgLatency,
                latencyUnit: 'milliseconds',
                successfulRuns,
                totalRuns: runs
            });
        }

        await cleanupTestData(contract, assetId, userId);
        await cleanupTestData(contract, newAssetId, newUserId);
        await fs.writeFile(
            path.join(__dirname, 'api_call_times_benchmark.json'),
            JSON.stringify(results, null, 2)
        );
        return results;
    } catch (error) {
        console.error('Error in benchmarkApiCallTimes:', error.message);
        throw error;
    } finally {
        if (gateway) await gateway.disconnect();
    }
}

async function benchmarkCreateAsset() {
    const runs = 50;
    const batchSize = 5;
    let gateway;
    const assetIds = [];

    try {
        gateway = await connectToUserGateway(USERNAME, 'owner');
        const network = await gateway.getNetwork(CHANNEL_NAME);
        const contract = network.getContract(CHAINCODE_NAME);

        let totalTime = 0;
        let successfulRuns = 0;

        for (let batch = 0; batch < runs; batch += batchSize) {
            const promises = [];
            for (let i = batch; i < Math.min(batch + batchSize, runs); i++) {
                promises.push(
                    (async () => {
                        const assetId = generateUniqueId('asset');
                        assetIds.push(assetId);
                        const metaData = JSON.stringify({ description: 'Test asset' });
                        const policyAttributes = [
                            {
                                interest: ['tech'],
                                languages: ['en']
                            }
                        ];
                        const policySet = JSON.stringify(policyAttributes);
                        const publicKeyOwner = 'dummy-public-key';
                        const now = new Date().toISOString();
                        const owner = USERNAME;
                        const name = 'test-asset';
                        const cid = 'dummy-cid';
                        const prevCid = '';
                        const key = generateRandomAccessKey();
                        const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
                        const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

                        const args = [
                            assetId,
                            metaData,
                            policySet,
                            publicKeyOwner,
                            now,
                            now,
                            owner,
                            name,
                            cid,
                            prevCid,
                            hashAccessKey,
                            JSON.stringify(fragmentsMap),
                            JSON.stringify(hashedAttributes),
                            JSON.stringify([
                                {
                                    interest: ['tech'],
                                    languages: ['en']
                                }
                            ]),
                        ];

                        const outcome = await measureFunction(contract, 'CreateAsset', args, false);
                        return outcome.duration;
                    })()
                );
            }

            const batchResults = await Promise.all(promises);
            for (const duration of batchResults) {
                if (duration >= 0) {
                    totalTime += duration;
                    successfulRuns++;
                }
            }
            console.log(`Completed batch ${batch / batchSize + 1}/${Math.ceil(runs / batchSize)}`);
            await new Promise((resolve) => setTimeout(resolve, DELAY_MS));
        }

        console.log('Cleaning up assets...');
        await cleanupAssetsBatch(contract, assetIds);

        const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;

        const output = {
            runs,
            avgLatency,
            latencyUnit: 'milliseconds',
            successfulRuns,
            totalRuns: runs
        };

        await fs.writeFile(
            path.join(__dirname, 'create_asset_benchmark.json'),
            JSON.stringify(output, null, 2)
        );

        return output;
    } catch (error) {
        console.error('Error in benchmarkCreateAsset:', error.message);
        throw error;
    } finally {
        if (gateway) await gateway.disconnect();
    }
}

async function benchmarkQueryLatency() {
    const concurrencyLevels = [5, 80, 200, 400, 600, 1000];
    const results = [];
    let gateway;
    try {
        gateway = await connectToUserGateway(USERNAME, 'owner');
        const network = await gateway.getNetwork(CHANNEL_NAME);
        const contract = network.getContract(CHAINCODE_NAME);

        const testData = await setupTestData(contract);
        const { userId, assetId, owner } = testData || {};

        for (const concurrency of concurrencyLevels) {
            const readPromises = Array.from({ length: concurrency }, () =>
                measureFunction(contract, 'ReadAsset', [assetId], true)
            );
            const readStart = performance.now();
            const readOutcomes = await Promise.all(readPromises);
            const readTotalTime = (performance.now() - readStart) / 1000;
            const validReadDurations = readOutcomes.filter((o) => o.duration >= 0).map(o => o.duration);
            const readAvgLatency =
                validReadDurations.length > 0
                    ? validReadDurations.reduce((sum, latency) => sum + latency, 0) / validReadDurations.length
                    : -1;
            const readTPS = validReadDurations.length / readTotalTime;

            const assetsPromises = Array.from({ length: concurrency }, () =>
                measureFunction(contract, 'GetAssetsByOwnerAndName', [owner, 'TestAsset', 'DEMO'], true)
            );
            const assetsStart = performance.now();
            const assetsOutcomes = await Promise.all(assetsPromises);
            const assetsTotalTime = (performance.now() - assetsStart) / 1000;
            const validAssetsDurations = assetsOutcomes.filter((o) => o.duration >= 0).map(o => o.duration);
            const assetsAvgLatency =
                validAssetsDurations.length > 0
                    ? validAssetsDurations.reduce((sum, latency) => sum + latency, 0) / validAssetsDurations.length
                    : -1;
            const assetsTPS = validAssetsDurations.length / assetsTotalTime;

            results.push({
                concurrency,
                readAssetAvgLatency: readAvgLatency.toFixed(3),
                readAssetTPS: readTPS.toFixed(2),
                getAssetsByOwnerAndNameAvgLatency: assetsAvgLatency.toFixed(3),
                getAssetsByOwnerAndNameTPS: assetsTPS.toFixed(2)
            });
        }

        await fs.writeFile(
            path.join(__dirname, 'query_latency_benchmark.json'),
            JSON.stringify(results, null, 2)
        );

        await cleanupTestData(contract, assetId, userId);
        return results;
    } catch (error) {
        console.error('Error in benchmarkQueryLatency:', error.message);
        throw error;
    } finally {
        if (gateway) await gateway.disconnect();
    }
}


async function benchmarkPromoteDemote() {
    const results = [];
    let gateway = null;
    let contract = null;
    let testData = null;

    try {
        console.log('Connecting to gateway...');
        gateway = await connectToUserGateway(USERNAME, 'owner');
        const network = await gateway.getNetwork(CHANNEL_NAME);
        contract = network.getContract(CHAINCODE_NAME);

        console.log('Setting up test data...');
        testData = await setupTestData(contract);
        const { userId, assetId } = testData;
        const currentDate = new Date().toISOString();

        // Validate user existence
        let userExists = false;
        try {
            const userExistsResult = await contract.evaluateTransaction('UserExists', userId);
            userExists = userExistsResult && JSON.parse(userExistsResult.toString());
        } catch (error) {
            console.error(`Error validating user ${userId}:`, error.message);
        }
        if (!userExists) {
            throw new Error(`User ${userId} does not exist after setup`);
        }

        const functions = [
            {
                name: 'CheckAccess',
                args: [userId, assetId],
                isQuery: true,
                description: 'Check if user can get access'
            },
            {
                name: 'PromoteAccess',
                args: [userId, assetId, currentDate],
                isQuery: false,
                description: 'Promote user access'
            }
        ];

        for (const func of functions) {
            let totalTime = 0;
            let successfulRuns = 0;
            const totalRuns = 5;

            console.log(`Benchmarking ${func.name}...`);

            for (let i = 0; i < totalRuns; i++) {
                try {
                    const outcome = await measureFunction(contract, func.name, func.args, func.isQuery);
                    if (outcome.duration >= 0) {
                        totalTime += outcome.duration;
                        successfulRuns++;
                        console.log(`${func.name} run ${i + 1} successful, duration: ${outcome.duration}ms`);
                        if (func.name === 'PromoteAccess') {
                            // Verify promotion
                            const postPromoteAsset = await contract.evaluateTransaction('ReadAsset', assetId);
                            const postPromoteAssetData = postPromoteAsset ? JSON.parse(postPromoteAsset.toString()) : null;
                            console.log(`Post-promote asset state for run ${i + 1}:`, JSON.stringify(postPromoteAssetData, null, 2));
                        }
                    } else {
                        console.error(`${func.name} failed for run ${i + 1}, outcome:`, outcome);
                    }
                } catch (error) {
                    console.error(`Error measuring ${func.name} for run ${i + 1}:`, error.message);
                }
                await new Promise(resolve => setTimeout(resolve, 100));
            }

            const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;
            results.push({
                function: func.name,
                description: func.description,
                avgLatency,
                latencyUnit: 'milliseconds',
                successfulRuns,
                totalRuns
            });
        }

        console.log('Writing results to file...');
        await fs.writeFile(
            path.join(__dirname, 'promote_demote_benchmark.json'),
            JSON.stringify(results, null, 2)
        );

        return results;
    } catch (error) {
        console.error('Error in benchmarkPromoteDemote:', error.message);
        throw error;
    } finally {
        if (testData && contract) {
            console.log('Cleaning up test data...');
            await cleanupTestData(contract, testData.assetId, testData.userId);
        }
        if (gateway) {
            console.log('Disconnecting gateway...');
            await gateway.disconnect();
        }
    }
}



async function benchmarkPromotionCheckByAttributeCount() {
    const attributeCounts = [1, 10, 50, 100, 500, 1000];
    const runsPerCount = 5;
    const results = [];
    let gateway = null;
    let contract = null;
    let testData = null;
    const userIds = [];

    try {
        console.log('Connecting to gateway for promotion check benchmark...');
        gateway = await connectToUserGateway(USERNAME, 'owner');
        const network = await gateway.getNetwork(CHANNEL_NAME);
        const contract = network.getContract(CHAINCODE_NAME);

        console.log('Setting up test data for promotion check benchmark...');
        testData = await setupTestData(contract);
        const { assetId } = testData;

        for (const attributeCount of attributeCounts) {
            console.log(`Benchmarking CheckAccess with ${attributeCount} user attributes...`);

            let totalTime = 0;
            let successfulRuns = 0;
            let accessGrantedCount = 0;

            for (let run = 0; run < runsPerCount; run++) {
                const includeRequired = Math.random() < 0.5;
                const userId = generateUniqueId('user');
                userIds.push(userId);
                const policySet = generateUserPolicySet(attributeCount, includeRequired);
                const currentDate = new Date().toISOString();

                try {
                    // Delete if already exists
                    try {
                        await contract.submitTransaction('DeleteUser', userId);
                    } catch {}
                    
                    await contract.submitTransaction(
                        'CreateUser',
                        userId,
                        'requester',
                        currentDate,
                        'dummy-public-key',
                        policySet
                    );
                    console.log(`Created user ${userId} with ${attributeCount} attributes, required=${includeRequired}`);
                } catch (error) {
                    console.error(`Error creating user ${userId} with ${attributeCount} attributes:`, error.message);
                    continue;
                }

                const outcome = await measureFunction(contract, 'CheckAccess', [userId, assetId], true);
                if (outcome.duration >= 0) {
                    totalTime += outcome.duration;
                    successfulRuns++;
                    try {
                        const result = JSON.parse(outcome.result.toString());
                        if (result.access) {
                            accessGrantedCount++;
                            console.log(`CheckAccess for user ${userId}: Access granted`);
                        } else {
                            console.log(`CheckAccess for user ${userId}: Access denied`);
                        }
                    } catch (error) {
                        console.error(`Error parsing CheckAccess result for user ${userId}:`, error.message);
                    }
                }
            }

            const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;
            const accessGrantedRate = successfulRuns > 0 ? (accessGrantedCount / successfulRuns).toFixed(3) : 0;
            results.push({
                attributeCount,
                avgLatency,
                latencyUnit: 'milliseconds',
                successfulRuns,
                totalRuns: runsPerCount,
                accessGrantedCount,
                accessGrantedRate
            });

            console.log(`Completed ${attributeCount} attributes: avgLatency=${avgLatency}ms, successfulRuns=${successfulRuns}/${runsPerCount}, accessGrantedRate=${accessGrantedRate}`);
        }

        console.log('Writing promotion check benchmark results to file...');
        await fs.writeFile(
            path.join(__dirname, 'promotion_check_by_attributes_benchmark.json'),
            JSON.stringify(results, null, 2)
        );

        return results;
    } catch (error) {
        console.error('Error in benchmarkPromotionCheckByAttributeCount:', error.message);
        throw error;
    } finally {
        if (testData && contract) {
            console.log('Cleaning up test data for promotion check benchmark...');
            await cleanupTestData(contract, testData.assetId, null);
            for (const userId of userIds) {
                await cleanupTestData(contract, null, userId);
            }
        }
        if (gateway) {
            console.log('Disconnecting gateway for promotion check benchmark...');
            await gateway.disconnect();
        }
    }
}



async function testLeastPrivilege() {
    let gateway = null;
    let contract = null;
    let testData = null;
    const results = [];

    try {
        console.log('===== Starting Least Privilege Tests =====');
        // Connect to gateway
        gateway = await connectToUserGateway(USERNAME, 'owner');
        const network = await gateway.getNetwork(CHANNEL_NAME);
        contract = network.getContract(CHAINCODE_NAME);

        console.log('Setting up test data for least privilege tests...');
        testData = await setupTestData(contract);
        const { userId, assetId } = testData;
        const currentDate = new Date().toISOString();

        // Validate user and asset existence
        const userExists = await contract.evaluateTransaction('UserExists', userId).then(res => JSON.parse(res.toString()));
        if (!userExists) {
            throw new Error(`User ${userId} does not exist after setup`);
        }
        const assetExists = await contract.evaluateTransaction('AssetExists', assetId).then(res => JSON.parse(res.toString()));
        if (!assetExists) {
            throw new Error(`Asset ${assetId} does not exist after setup`);
        }

        // Test 1: Revoked user cannot access any files
        console.log('===== Test 1: Revoked User Cannot Access Any Files =====');
        console.log('Purpose: Verifies the principle of least privilege by ensuring a permanently revoked user cannot access any files.');
        try {
            // Grant initial access to ensure user can interact with the asset
            await contract.submitTransaction('GrantAccess', userId, assetId, currentDate);
            console.log(`Granted initial access for user ${userId} on asset ${assetId}`);

            // Revoke access permanently
            await contract.submitTransaction('RevokePermanentAccess', userId, assetId, currentDate);
            console.log(`Permanently revoked access for user ${userId} on asset ${assetId}`);

            // Check access
            const accessAfterRevoke = await measureFunction(contract, 'CheckAccess', [userId, assetId], true);
            if (accessAfterRevoke.duration >= 0 && !JSON.parse(accessAfterRevoke.result.toString()).access) {
                console.log(`SUCCESS: Revoked user ${userId} cannot access asset ${assetId}, enforcing least privilege`);
                results.push({ test: 'RevokedAccess', status: 'SUCCESS', description: 'Revoked user cannot access any files' });
            } else {
                console.log(`FAIL: Revoked user ${userId} can still access asset ${assetId}, violating least privilege`);
                results.push({ test: 'RevokedAccess', status: 'FAIL', description: 'Revoked user can access asset unexpectedly' });
            }
        } catch (error) {
            console.error(`Error in RevokedAccess test: ${error.message}`);
            results.push({ test: 'RevokedAccess', status: 'ERROR', description: 'Error during revoked access test', error: error.message });
        }
        console.log('=====');

        // Test 2: Promoted user cannot be promoted again
        console.log('===== Test 2: Promoted User Cannot Be Promoted Again =====');
        console.log('Purpose: Ensures the system prevents redundant promotion of an already promoted user, adhering to least privilege.');
        try {
            // Promote user
            await contract.submitTransaction('PromoteAccess', userId, assetId, currentDate);
            console.log(`Promoted user ${userId} for asset ${assetId}`);

            // Attempt to promote again
            const secondPromote = await measureFunction(contract, 'PromoteAccess', [userId, assetId, currentDate], false);
            if (secondPromote.duration === -1) {
                console.log(`SUCCESS: User ${userId} cannot be promoted again, preventing redundant privilege escalation`);
                results.push({ test: 'PromoteTwice', status: 'SUCCESS', description: 'Cannot promote an already promoted user' });
            } else {
                console.log(`FAIL: User ${userId} was promoted again unexpectedly, violating least privilege`);
                results.push({ test: 'PromoteTwice', status: 'FAIL', description: 'User was promoted again unexpectedly' });
            }
        } catch (error) {
            console.error(`Error in PromoteTwice test: ${error.message}`);
            results.push({ test: 'PromoteTwice', status: 'ERROR', description: 'Error during promote twice test', error: error.message });
        }
        console.log('=====');

        // Save results
        console.log('Writing least privilege test results to file...');
        await fs.writeFile(
            path.join(__dirname, 'least_privilege_test.json'),
            JSON.stringify(results, null, 2)
        );

        return results;
    } catch (error) {
        console.error('Error in testLeastPrivilege:', error.message);
        throw error;
    } finally {
        // Cleanup
        if (testData && contract) {
            console.log('Cleaning up test data for least privilege tests...');
            await cleanupTestData(contract, testData.assetId, testData.userId);
        }
        if (gateway) {
            console.log('Disconnecting gateway for least privilege tests...');
            await gateway.disconnect();
        }
        console.log('===== Least Privilege Tests Completed =====');
    }
}
async function runAllBenchmarks() {
    const iterationCounts = [5];
    const results = {};

    try {
        console.log('Starting benchmarks...');

        console.log('Running API and query benchmark...');
        results.apiAndQuery = await runBenchmarkWithIterations(benchmarkApiAndQuery, iterationCounts, 'api_and_query');
        console.log('Completed API and query benchmark');

        console.log('Running create asset benchmark...');
        results.createAsset = await runBenchmarkWithIterations(benchmarkCreateAsset, iterationCounts, 'create_asset');
        console.log('Completed create asset benchmark');

        console.log('Running promote/demote benchmark...');
        results.promoteApi = await runBenchmarkWithIterations(benchmarkPromoteDemote, iterationCounts, 'promote_api');
        console.log('Completed promote/demote benchmark');

        console.log('Running promotion check by attribute count benchmark...');
        results.promotionCheckByAttributeCount = await runBenchmarkWithIterations(benchmarkPromotionCheckByAttributeCount, iterationCounts, 'promotion_check_by_attribute_count');
        console.log('Completed promotion check by attribute count benchmark');

        console.log('Running least privilege test...');
        results.leastPrivilege = await testLeastPrivilege();
        console.log('Completed least privilege test');

        console.log('Benchmarks and tests completed successfully.');
        console.log('Results:', JSON.stringify(results, null, 2));

        // Save all results as JSON
        await fs.writeFile(path.join(__dirname, 'all_benchmarks_and_tests_avg.json'), JSON.stringify(results, null, 2));
        console.log('Saved all JSON results to all_benchmarks_and_tests_avg.json');

        return results;
    } catch (error) {
        console.error('Error running benchmarks and tests:', error.message);
        throw error;
    }
}
runAllBenchmarks()
    .then((results) => {
        console.log('Benchmarks and tests completed successfully.');
        console.log('Results:', JSON.stringify(results, null, 2));
    })
    .catch((error) => {
        console.error('Benchmarking and testing failed:', error.stack);
        process.exit(1);
    });