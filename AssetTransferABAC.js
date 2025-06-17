// AssetTransferABAC.js
const stringify = require('json-stringify-deterministic');
const sortKeysRecursive = require('sort-keys-recursive');
const crypto = require('crypto');
const { split, join } = require('shamir');
const { TextDecoder } = require('node:util');

class AssetTransferABAC {
    async CreateUser(stub, username, role, createdAt, publicKey, policySet) {
        const exists = await this.UserExists(stub, username);
        if (exists) {
            throw new Error(`User ${username} already exists`);
        }
    
        const user = {
            Username: username,
            Role: role,
            CreatedAt: createdAt,
            PublicKey: publicKey,
            PolicySet: JSON.parse(policySet)
        };
    
        await stub.putState(username, Buffer.from(stringify(sortKeysRecursive(user))));
        return user;
    }

    async hashKeyValuePairs(policyAttributes) {
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

    async UserExists(stub, username) {
        const userJSON = await stub.getState(username);
        return userJSON && userJSON.length > 0;
    }

    async GetUser(stub, username) {
        const userJSON = await stub.getState(username);
        if (!userJSON || userJSON.length === 0) {
            throw new Error(`User ${username} does not exist`);
        }
        return userJSON.toString();
    }

async GetAssetsByOwnerAndName(stub, owner, name, userType) {
    try {
        const startKey = '';
        const endKey = '';
        const resultsIterator = await stub.getStateByRange(startKey, endKey);
        const assets = [];

        for await (const { key, value } of resultsIterator) {
            try {
                const strValue = Buffer.from(value).toString('utf8');
                let record;
                try {
                    record = JSON.parse(strValue);
                    if (record.owner === owner && record.name === name && record.userType === userType) {
                        assets.push(record);
                    }
                } catch (err) {
                    console.log(`Error parsing asset at key ${key}:`, err);
                }
            } catch (err) {
                console.log(`Error processing asset at key ${key}:`, err);
            }
        }
        return assets;
    } catch (err) {
        throw new Error(`Failed to get assets: ${err.message}`);
    }
}
async AssetExists(stub, id) {
    const assetJSON = await stub.getState(id);
    return !!assetJSON && assetJSON.length > 0;
}

    async DeleteAsset(stub, id) {
        const exists = await this.AssetExists(stub, id);
        if (!exists) {
            throw new Error(`The asset ${id} does not exist`);
        }
        await stub.deleteState(id);
        return `Asset ${id} deleted successfully`;
    }

    async CreateAsset(stub, id, metaData, policySet, publicKeyOwner, releaseAt, updatedAt, owner, name, cid, PrevCid, hashAccessKey, fragmentsMap, hashedAttributes, promoteAttributes) {
        const exists = await this.AssetExists(stub, id);
        
        if (exists) {
            throw new Error(`The asset ${id} already exists`);
        }

        const asset = {
            type: "DEMO",
            ID: id,
            MetaData: metaData,
            policySet: JSON.parse(policySet),
            publicKeyOwner: publicKeyOwner,
            ReleasedAt: releaseAt,
            UpdatedAt: updatedAt,
            Requesters: [],
            revokedAccess: [],
            promotedAccess: [],
            owner: owner,
            name: name,
            cid: cid,
            PrevCid: PrevCid,
            hashAccessKey: hashAccessKey,
            fragmentsMap: JSON.parse(fragmentsMap),
            hashedAttributes: JSON.parse(hashedAttributes),
            promoteAttributes: JSON.parse(promoteAttributes)
        };

        await stub.putState(id, Buffer.from(stringify(sortKeysRecursive(asset))));
        return asset;
    }

    async ReadAsset(stub, id) {
        const assetJSON = await stub.getState(id);
        if (!assetJSON || assetJSON.length === 0) {
            throw new Error(`The asset ${id} does not exist`);
        }
        return assetJSON.toString();
    }

    async UpdateAsset(stub, id, metaData, policySet, publicKeyOwner, releaseAt, updatedAt, owner, name, cid, PrevCid, hashAccessKey, fragmentsMap, hashedAttributes, promoteAttributes) {
        const exists = await this.AssetExists(stub, id);
        if (!exists) {
            throw new Error(`The asset ${id} does not exist`);
        }
    
        const assetString = await this.ReadAsset(stub, id);
        const existingAsset = JSON.parse(assetString);
    
        let parsedPromoteAttributes;
        try {
            parsedPromoteAttributes = typeof promoteAttributes === 'string' ? JSON.parse(promoteAttributes) : promoteAttributes;
            if (!Array.isArray(parsedPromoteAttributes)) {
                parsedPromoteAttributes = [parsedPromoteAttributes];
            }
            parsedPromoteAttributes = parsedPromoteAttributes.filter(attr => {
                const interests = Array.isArray(attr.interest) ? attr.interest : [];
                const languages = Array.isArray(attr.languages) ? attr.languages : [];
                return interests.length > 0 || languages.length > 0;
            });
            if (parsedPromoteAttributes.length === 0) {
                throw new Error("promoteAttributes must contain at least one valid policy");
            }
        } catch (error) {
            throw new Error(`Invalid promoteAttributes format: ${error.message}`);
        }
    
        let parsedPolicySet = policySet;
        let parsedFragmentsMap = fragmentsMap;
        let parsedHashedAttributes = hashedAttributes;
        try {
            parsedPolicySet = typeof policySet === 'string' ? JSON.parse(policySet) : policySet;
            parsedFragmentsMap = typeof fragmentsMap === 'string' ? JSON.parse(fragmentsMap) : fragmentsMap;
            parsedHashedAttributes = typeof hashedAttributes === 'string' ? JSON.parse(hashedAttributes) : hashedAttributes;
        } catch (error) {
            throw new Error(`Invalid JSON format in policySet, fragmentsMap, or hashedAttributes: ${error.message}`);
        }
    
        const updatedAsset = {
            type: "DEMO",
            ID: id,
            MetaData: metaData,
            policySet: parsedPolicySet,
            publicKeyOwner: publicKeyOwner,
            ReleasedAt: releaseAt,
            UpdatedAt: updatedAt,
            Requesters: existingAsset.Requesters || [],
            revokedAccess: existingAsset.revokedAccess || [],
            promotedAccess: existingAsset.promotedAccess || [],
            owner: owner,
            name: name,
            cid: cid,
            PrevCid: PrevCid,
            hashAccessKey: hashAccessKey,
            fragmentsMap: parsedFragmentsMap,
            hashedAttributes: parsedHashedAttributes,
            promoteAttributes: parsedPromoteAttributes
        };
    
        await stub.putState(id, Buffer.from(stringify(sortKeysRecursive(updatedAsset))));
        return updatedAsset;
    }
    
    async RevokePermanentAccess(stub, username, assetID, revokedAt) {
        const assetString = await this.ReadAsset(stub, assetID);
        if (!assetString) {
            throw new Error(`Asset with ID ${assetID} not found.`);
        }
        
        const asset = JSON.parse(assetString);
    
        if (!asset.revokedAccess) {
            asset.revokedAccess = [];
        }

        asset.revokedAccess.push({
            username: username,
            type: 'permanent',
            revokedAt: revokedAt
        });
    
        await stub.putState(assetID, Buffer.from(stringify(sortKeysRecursive(asset))));
        return asset;
    }

    async RestoreAccess(stub, username, assetID, restoredAt) {
        const assetString = await this.ReadAsset(stub, assetID);
        if (!assetString) {
            throw new Error(`Asset with ID ${assetID} not found.`);
        }
        
        const asset = JSON.parse(assetString);
    
        if (!asset.revokedAccess || asset.revokedAccess.length === 0) {
            throw new Error(`No revoked access found for asset ${assetID}`);
        }

        const initialLength = asset.revokedAccess.length;
        asset.revokedAccess = asset.revokedAccess.filter(access => 
            !(access.username === username && access.type === 'permanent')
        );

        if (asset.revokedAccess.length === initialLength) {
            throw new Error(`User ${username} was not permanently revoked for asset ${assetID}`);
        }

        if (!asset.accessHistory) {
            asset.accessHistory = [];
        }
        asset.accessHistory.push({
            username: username,
            action: 'restored',
            restoredAt: restoredAt
        });
    
        await stub.putState(assetID, Buffer.from(stringify(sortKeysRecursive(asset))));
        return asset;
    }



async PromoteAccess(stub, username, assetID, promotedAt) {
    console.log(`[PromoteAccess] Processing for user ${username}, asset ${assetID}`);
    const userString = await this.GetUser(stub, username); // Changed from this.ReadUser
    if (!userString) {
        throw new Error(`User ${username} does not exist`);
    }
    const user = JSON.parse(userString);
    const userPolicySet = user.PolicySet;

    const assetString = await this.ReadAsset(stub, assetID);
    if (!assetString) {
        throw new Error(`Asset with ID ${assetID} not found`);
    }
    const asset = JSON.parse(assetString);
    console.log(`[PromoteAccess] Initial asset state: ${JSON.stringify(asset)}`);

    if (!asset.promoteAttributes) {
        throw new Error(`Asset ${assetID} has no promoteAttributes defined`);
    }
    const promoteAttributes = Array.isArray(asset.promoteAttributes) ? asset.promoteAttributes : JSON.parse(asset.promoteAttributes);
    console.log(`[PromoteAccess] promoteAttributes: ${JSON.stringify(promoteAttributes)}`);
    console.log(`[PromoteAccess] userPolicySet: ${JSON.stringify(userPolicySet)}`);

    const hasMatchingAttributes = promoteAttributes.every(attr => {
        const requiredInterests = Array.isArray(attr.interest) ? attr.interest : [];
        const requiredLanguages = Array.isArray(attr.languages) ? attr.languages : [];
        return userPolicySet.some(userPolicy => {
            const userInterests = Array.isArray(userPolicy.interest) ? userPolicy.interest : [];
            const userLanguages = Array.isArray(userPolicy.languages) ? userPolicy.languages : [];
            const interestMatch = requiredInterests.every(i => userInterests.includes(i));
            const languageMatch = requiredLanguages.every(l => userLanguages.includes(l));
            console.log(`[PromoteAccess] Checking attribute: promoteAttr=${JSON.stringify(attr)}, userPolicy=${JSON.stringify(userPolicy)}, interestMatch=${interestMatch}, languageMatch=${languageMatch}`);
            return interestMatch && languageMatch;
        });
    });

    if (!hasMatchingAttributes) {
        throw new Error(`User ${username} does not have required attributes to be promoted for asset ${assetID}`);
    }

    if (!asset.promotedAccess) {
        asset.promotedAccess = [];
    }
    if (asset.promotedAccess.some(access => access.username === username)) {
        throw new Error(`User ${username} already has promoted access for asset ${assetID}`);
    }

    asset.promotedAccess.push({ username, promotedAt });
    console.log(`[PromoteAccess] Updated asset.promotedAccess: ${JSON.stringify(asset.promotedAccess)}`);
    const serializedAsset = Buffer.from(JSON.stringify(sortKeysRecursive(asset)));
    console.log(`[PromoteAccess] Serializing asset: ${serializedAsset.toString()}`);
    await stub.putState(assetID, serializedAsset);
    console.log(`[PromoteAccess] State updated for asset ${assetID}`);
    return asset;
}



async DemoteAccess(stub, username, assetID, demotedAt) {
    console.log(`[DemoteAccess] Processing for user ${username}, asset ${assetID}`);
    const assetString = await this.ReadAsset(stub, assetID);
    if (!assetString) {
        throw new Error(`Asset with ID ${assetID} not found.`);
    }
    const asset = JSON.parse(assetString);
    console.log(`[DemoteAccess] Initial asset state: ${JSON.stringify(asset)}`);

    if (!asset.promotedAccess) {
        asset.promotedAccess = [];
    }
    const initialLength = asset.promotedAccess.length;
    asset.promotedAccess = asset.promotedAccess.filter(access => access.username !== username);
    console.log(`[DemoteAccess] Updated promotedAccess: ${JSON.stringify(asset.promotedAccess)}`);
    if (asset.promotedAccess.length === initialLength && initialLength > 0) {
        throw new Error(`User ${username} was not found in promoted access for asset ${assetID}`);
    }
    const serializedAsset = Buffer.from(JSON.stringify(sortKeysRecursive(asset)));
    console.log(`[DemoteAccess] Serializing asset: ${serializedAsset.toString()}`);
    await stub.putState(assetID, serializedAsset);
    console.log(`[DemoteAccess] State updated for asset ${assetID}`);
    return asset;
}

    async CheckAccess(stub, username, assetID) {
        let user = await this.GetUser(stub, username);
        user = JSON.parse(user);
        let userPolicySet;

        try {
            if (typeof user.PolicySet === 'string') {
                userPolicySet = JSON.parse(user.PolicySet);
            } else if (Array.isArray(user.PolicySet)) {
                userPolicySet = user.PolicySet;
            } else if (typeof user.PolicySet === 'object') {
                userPolicySet = [user.PolicySet];
            } else {
                throw new Error("PolicySet is neither a valid JSON string, object, nor an array");
            }
            if (!Array.isArray(userPolicySet)) {
                throw new Error("PolicySet should be an array");
            }
        } catch (error) {
            console.error(`Invalid PolicySet format for user ${username}:`, user.PolicySet);
            throw new Error(`Invalid JSON format for PolicySet of user ${username}: ${error.message}`);
        }

        const assetJSON = await stub.getState(assetID);
        if (!assetJSON || assetJSON.length === 0) {
            throw new Error(`Asset ${assetID} does not exist`);
        }
        const asset = JSON.parse(assetJSON.toString());
        if (typeof asset.policySet === 'string') {
            asset.policySet = JSON.parse(asset.policySet);
        }

        const isPermanentRevoked = asset.revokedAccess && asset.revokedAccess.some(access => 
            access.username === username && access.type === 'permanent'
        );
        if (isPermanentRevoked) {
            return { access: false };
        }

        const allAssets = await this.GetAllAssets(stub);
        const parsedAssets = allAssets;
        const isBlockedByOwner = parsedAssets.some(({ Record }) => {
            if (Record.owner === asset.owner && Record.revokedAccess) {
                return Record.revokedAccess.some(access => 
                    access.username === username && access.type === 'permanent'
                );
            }
            return false;
        });
        if (isBlockedByOwner) {
            return { access: false };
        }

        const userHasAccess = asset.policySet.every(assetPolicy => 
            userPolicySet.some(userPolicy => {
                return Object.keys(assetPolicy).every(key => {
                    if (!userPolicy[key] || !Array.isArray(userPolicy[key])) {
                        return false;
                    }
                    return assetPolicy[key].every(value => userPolicy[key].includes(value));
                });
            })
        );

        if (!userHasAccess) {
            return { access: false };
        }

        const extractedShares = {};
        asset.fragmentsMap.slice(0, asset.hashedAttributes.length).forEach((fragment, index) => {
            extractedShares[index + 1] = fragment.share;
        });
        const result = {};
        for (const key in extractedShares) {
            if (Object.hasOwnProperty.call(extractedShares, key)) {
                const numbers = Object.values(extractedShares[key]);
                result[key] = new Uint8Array(numbers);
            }
        }
        const recovered = join(result);
        const utf8Decoder = new TextDecoder();
        const recoveredAccessKey = utf8Decoder.decode(recovered);
        return { access: true, owner: asset.owner, key: recoveredAccessKey };
    }

    async GrantAccess(stub, username, assetID, grantedAt) {
        const assetString = await this.ReadAsset(stub, assetID);
        const asset = JSON.parse(assetString);

        asset.Requesters.push({ username: username, grantedAt: grantedAt });
        await stub.putState(assetID, Buffer.from(stringify(sortKeysRecursive(asset))));
        return asset;
    }



    async DeleteUser(stub, username) {
        const exists = await this.UserExists(stub, username);
        if (!exists) {
            throw new Error(`User ${username} does not exist`);
        }
        await stub.deleteState(username);
        return `User ${username} deleted successfully`;
    }

    async DeleteAssetPublic(stub, id) {
        const exists = await this.AssetExists(stub, id);
        if (!exists) {
            throw new Error(`The asset ${id} does not exist`);
        }
        await stub.deleteState(id);
        return `Asset ${id} deleted successfully`;
    }

    async TransferAsset(stub, id, newPublicKeyOwner) {
        const assetString = await this.ReadAsset(stub, id);
        const asset = JSON.parse(assetString);
        const oldOwner = asset.publicKeyOwner;
        asset.publicKeyOwner = newPublicKeyOwner;
        asset.UpdatedAt = new Date().toISOString();

        await stub.putState(id, Buffer.from(stringify(sortKeysRecursive(asset))));
        return oldOwner;
    }
async GetAllAssets(stub) {
    try {
        const startKey = '';
        const endKey = '';
        const resultsIterator = await stub.getStateByRange(startKey, endKey);
        const allResults = [];
        
        for await (const { key, value } of resultsIterator) {
            try {
                const strValue = Buffer.from(value).toString('utf8');
                let record;
                try {
                    record = JSON.parse(strValue);
                    allResults.push(record);
                } catch (err) {
                    console.log(`Error parsing asset at key ${key}:`, err);
                }
            } catch (err) {
                console.log(`Error processing asset at key ${key}:`, err);
            }
        }
        return allResults;
    } catch (err) {
        throw new Error(`Failed to get assets: ${err.message}`);
    }
}

    async GetAssetHistory(stub, id) {
        const history = [];
        const iterator = await stub.getHistoryForKey(id);
        let result;
        while (true) {
            result = await iterator.next();
            if (result.done) {
                await iterator.close();
                break;
            }
            const tx = {
                txId: result.value.txId,
                timestamp: new Date(result.value.timestamp.getSeconds() * 1000).toISOString(),
                isDelete: result.value.isDelete,
                value: result.value.value ? result.value.value.toString('utf8') : null,
            };
            try {
                tx.value = JSON.parse(tx.value);
            } catch (e) {
                console.log('Non-JSON value in history:', tx.value);
            }
            history.push(tx);
        }
        return history;
    }
}

module.exports = AssetTransferABAC;