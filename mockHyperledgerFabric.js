// mockHyperledgerFabric.js
const AssetTransferABAC = require('./AssetTransferABAC');

class MockStub {
    constructor() {
        this.state = new Map();
        this.history = new Map();
    }

async putState(key, value) {
    console.log(`[MockStub] Putting state for key ${key}: ${value.toString()}`);
    this.state.set(key, value);
    // Simulate async write
    await new Promise(resolve => setTimeout(resolve, 10));
    return Promise.resolve();
}

async getState(key) {
    const value = this.state.get(key) || null;
    console.log(`[MockStub] Getting state for key ${key}: ${value ? value.toString() : null}`);
    // Simulate async read
    await new Promise(resolve => setTimeout(resolve, 10));
    return Promise.resolve(value);
}

    async deleteState(key) {
        this.state.delete(key);
        const history = this.history.get(key) || [];
        history.push({
            txId: `tx-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
            timestamp: { getSeconds: () => Math.floor(Date.now() / 1000) },
            isDelete: true,
            value: null
        });
        this.history.set(key, history);
    }

async getStateByRange(startKey, endKey) {
    const results = [];
    for (const [key, value] of this.state) {
        if (key >= startKey && key <= endKey) {
            results.push({ key, value });
        }
    }
    let index = 0;
    const iterator = {
        async next() {
            if (index >= results.length) {
                return { value: undefined, done: true };
            }
            const result = results[index++];
            return { value: result, done: false };
        },
        async close() {
            // Simulate closing the iterator (no-op for mock)
        },
        [Symbol.asyncIterator]() {
            return this;
        }
    };
    return iterator;
}

    async getHistoryForKey(key) {
        const history = this.history.get(key) || [];
        return {
            async next() {
                const entry = history.shift();
                return {
                    value: entry,
                    done: !entry
                };
            },
            async close() {}
        };
    }

    resetState() {
        this.state.clear();
        this.history.clear();
    }
}

class MockContract {
    constructor(stub) {
        this.stub = stub;
        this.chaincode = new AssetTransferABAC();
    }

    async evaluateTransaction(funcName, ...args) {
        if (typeof this.chaincode[funcName] !== 'function') {
            throw new Error(`Function ${funcName} does not exist on contract`);
        }
        const result = await this.chaincode[funcName](this.stub, ...args);
        const serializedResult = result === null || result === undefined ? {} : result;
        return Buffer.from(JSON.stringify(serializedResult));
    }

    async submitTransaction(funcName, ...args) {
        return this.evaluateTransaction(funcName, ...args);
    }
}

class MockNetwork {
    constructor() {
        this.contract = null;
    }

    getContract(chaincodeName) {
        if (!this.contract) {
            this.contract = new MockContract(new MockStub());
        }
        return this.contract;
    }
}

class MockGateway {
    constructor() {
        this.network = new MockNetwork();
    }

    async getNetwork(channelName) {
        return this.network;
    }

    async connect() {
        // Simulate connection
    }

    async disconnect() {
        // Simulate disconnection
    }
}

class HyperledgerFabric {
    constructor() {
        this.gateway = new MockGateway();
    }

    async connectToGateway(username, userType) {
        await this.gateway.connect();
        return this.gateway;
    }
}

module.exports = HyperledgerFabric;