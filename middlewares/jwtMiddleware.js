
const redis     = require('redis');
const jwt       = require('jsonwebtoken');
const fs        = require('fs');
const path = require( "path" );

const checkIfJwtIsValid = async (req, res, next) => {
    try {
        const client = redis.createClient();

        await client.connect();
    
        // Check if any valid JWT is present and return it
        let jwtToken = await client.get(req.body.client_id);
        
        if (jwtToken) {
            var cert = fs.readFileSync(path.resolve(__dirname, '../keys/public.pem'));

            jwt.verify(req.body.jwt, cert, function(err, decoded) {
                if (err) {
                    res.status(401).send('JWT is not valid!');        
                } 

                // Check if jwt contains same client_id
                if (decoded.client_id == req.body.client_id) {
                    next()
                } else {
                    res.status(401).send('JWT is not valid!');
                }
            });
        } else {
            res.status(401).send('JWT is not valid!');
        }
    } catch (e) {
        res.status(401).send('JWT is not valid!');
    }
}

module.exports = {
    checkIfJwtIsValid: checkIfJwtIsValid,
};