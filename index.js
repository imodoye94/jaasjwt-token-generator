const functions = require('@google-cloud/functions-framework');
const { SignJWT, importPKCS8 } = require('jose');

// RS256 private key in PEM format is stored in an environment variable
const PEM_PRIVATE_KEY = process.env.RS256_PRIVATE_KEY;

// Cloud Function: jaasjwt
exports.jaasjwt = async (req, res) => {

    // Stricter CORS setup to only allow requests from our domain
    res.set('Access-Control-Allow-Origin', 'https://backend.hib.to');
    res.set('Access-Control-Allow-Methods', 'POST');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      // Send response to OPTIONS requests
      res.status(204).send('');
      return;
    }  
    else if (req.method !== 'POST') {
      // Only allow POST
      return res.status(405).end();
    }

    // Straightforward verification of the Authorization header
    const expectedApiKey = `Bearer ${process.env.APIKEY_FOR_VERIFYFRONTEND}`;
    const providedApiKey = req.headers.authorization;

    if (providedApiKey !== expectedApiKey) {
      // Respond if the Authorization header does not match the expected API key
      return res.status(401).send('Unauthorized Request');
    }

    // If the API key verification is successful, proceed with the main logic

    // Check for required fields in the request body
    const requiredFields = ['id', 'name', 'avatar', 'email', 'moderator', 'livestreaming', 'recording', 'moderation', 'room'];
    for (const field of requiredFields) {
        if (!req.body.hasOwnProperty(field)) {
            res.status(400).send(`Missing required parameter: ${field}`);
            return;
        }
    }

    const { id, name, avatar, email, moderator, livestreaming, recording, moderation, room } = req.body;

    try {
        // Convert PEM private key to JWK for signing
        const jwkPrivateKey = await importPKCS8(PEM_PRIVATE_KEY, 'RS256');

        // Construct and sign the JWT
        const token = await new SignJWT({
            aud: "jitsi",
            context: {
                user: {
                    id,
                    name,
                    avatar,
                    email,
                    moderator: moderator.toString() // Ensure it's a string
                },
                features: {
                    livestreaming: livestreaming.toString(),
                    recording: recording.toString(),
                    moderation: moderation.toString()
                }
            },
            exp: Math.floor(Date.now() / 1000) + (1 * 1 * 86400), // Current time + ~1 day
            iss: "chat",
            nbf: Math.floor(Date.now() / 1000),
            room,
            sub: "vpaas-magic-cookie-098f04f2b4b64b6cbd0b6490cd5f2319"
        })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'vpaas-magic-cookie-098f04f2b4b64b6cbd0b6490cd5f2319/f682a6' })
        .sign(jwkPrivateKey);

        // Send the JWT back to the client
        res.status(200).json({ token });
    } catch (error) {
        console.error('Error generating JWT:', error);
        res.status(500).send('Error generating JWT');
    }
};




