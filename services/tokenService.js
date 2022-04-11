const dbo       = require('../db/conn');
const crypto    = require('crypto');
const config    = require('dotenv').config();
const redis     = require('redis');
const jwt       = require('jsonwebtoken');
const fs        = require('fs');
const path = require( "path" );

const TOKEN_STATUSES = {
    'VALID'     : 1,
    'EXPIRED'   : 2
};

/**
 * 
 * @param {*} userMaiarAddress 
 * @param {*} tokenType 
 * @returns 
 */
const checkUserToken = async function (req, res) {
    const db = dbo.getDb();
    
    return await db.collection('tokens').findOne({ client_id: req.body.client_id, status: TOKEN_STATUSES.VALID}, function(err, result) {
        if (err) {
            throw new Error();
        } else {
            if (result) {
                res.json(result);
            } else {
                let token = generateTokenModel(req.body.client_id, req.body.tokenType, req.body.public_key);

                db
                .collection('tokens')
                .insertOne(token, function (err, result) {
                    if (err) {
                        throw new Error();
                    } else {
                        res.json(token);
                    }
                });
            }
        }
    })
}

/**
 * 
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
const isTokenSignatureValid = async function (req, res ,next) {
    const db = dbo.getDb();

    const token = await db.collection('tokens').findOne({ value: req.body.token, status: TOKEN_STATUSES.VALID}, function(err, result) {
        if (err) {
            throw new Error(err);
        } else {
            if (result) {
                // First check timestamp 
                const now = Date.now();
                
                if (((now - result.created_at) / 1000) > process.env.TOKEN_VALIDITY_SECONDS) {
                    db.collection('tokens').updateOne(
                        {value: req.body.token},
                        {$set: {status: TOKEN_STATUSES.EXPIRED}},
                        {upsert: true},
                        function(err, result) {
                            if (err) {
                                throw new Error(err);
                            }

                            console.log('Token updated with expired status')
                            res.status(401).send('Token is expired!')
                    });
                } else {
                    const isVerified = crypto.verify(
                        "sha256",
                        Buffer.from(req.body.token),
                        {
                        key: result.public_key,
                        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                        },
                        Buffer.from(req.body.signature, 'base64')
                    );
            
                    if (isVerified) {
                        next();
                    } else {
                        throw new Error('Token is not valid!');
                    }
                }
            } else {
                throw new Error(err);
            }
        }
    })
}

/**
 * 
 * @param {*} req 
 * @param {*} res 
 */
const fetchOrCreateUserCredentials = async (req, res) => {
    const client = redis.createClient();

    await client.connect();
    
    // Check if any valid JWT is present and return it
    let jwtToken = await client.get(req.body.client_id);

    if (!jwtToken) {
        const privateKey    = fs.readFileSync(path.resolve(__dirname, '../keys/private.pem'));
        const token         = jwt.sign({ client_id: req.body.client_id }, privateKey, { algorithm: 'RS256'});
    
        await client.set(req.body.client_id, token, {EX: process.env.JWT_TTL});
        jwtToken = await client.get(req.body.client_id);
    }

      res.json({jwtToken: jwtToken})
}

/**
 * 
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
const performAction = async (req, res) => {
    const db = dbo.getDb();

    // Do some stuff
    // --
    // -- 

    db.collection('tokens').updateOne(
        {value: req.body.token},
        {$set: {status: TOKEN_STATUSES.EXPIRED}},
        {upsert: true},
        function(err, result) {
            if (err) {
                throw new Error(err);
            }

            console.log('Token updated with expired status');
    });

    return 'Action performed';
}

/**
 * 
 * @param {*} userMaiarAddress 
 * @param {*} tokenType 
 * @returns 
 */
function generateTokenModel(client_id, tokenType, public_key) {
    return {
        'client_id' : client_id,
        'public_key': public_key,
        'type'      : tokenType,
        'value'     : crypto.createHash('md5').update(client_id).digest('hex') + crypto.createHash('md5').update(Date.now().toString()).digest('hex'),
        'status'    : TOKEN_STATUSES.VALID, // Valid status for creation
        'created_at': Date.now(),
        'updated_at': Date.now()
    }
}

module.exports = {
    checkUserToken: checkUserToken,
    isTokenSignatureValid: isTokenSignatureValid,
    fetchOrCreateUserCredentials: fetchOrCreateUserCredentials,
    performAction: performAction
};