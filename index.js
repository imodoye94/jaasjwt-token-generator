const functions = require('@google-cloud/functions-framework');
const { SignJWT, importPKCS8 } = require('jose');
const fs = require('fs');
const path = require('path');

const KEY_PATH =
  process.env.RS256_PRIVATE_KEY_PATH
  || path.join(__dirname, 'jaaskey.pk');

let cachedPem = null;
let cachedJwkPrivateKey = null;

async function getSigningKey() {
  if (cachedJwkPrivateKey) return cachedJwkPrivateKey;

  if (!cachedPem) {
    cachedPem = fs.readFileSync(KEY_PATH, 'utf8');
  }

  cachedJwkPrivateKey = await importPKCS8(cachedPem, 'RS256');
  return cachedJwkPrivateKey;
}

/* Register the HTTP function with Functions Framework */
functions.http('jaasjwt', async (req, res) => {
  /* CORS: single-origin response based on allowlist */
  const allowedOrigins = new Set([
    'https://backend.mediverse.ai',
    'https://backend.hib.to',
  ]);
  const origin = req.headers.origin;

  if (origin && allowedOrigins.has(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
  }

  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }
  if (req.method !== 'POST') {
    res.status(405).end();
    return;
  }

  const expectedApiKey = `Bearer ${process.env.APIKEY_FOR_VERIFYFRONTEND}`;
  const providedApiKey = req.headers.authorization;

  if (providedApiKey !== expectedApiKey) {
    res.status(401).send('Unauthorized Request');
    return;
  }

  const requiredFields = [
    'id', 'name', 'avatar', 'email',
    'moderator', 'livestreaming', 'recording', 'moderation',
    'room'
  ];
  for (const field of requiredFields) {
    if (!Object.prototype.hasOwnProperty.call(req.body || {}, field)) {
      res.status(400).send(`Missing required parameter: ${field}`);
      return;
    }
  }

  const { id, name, avatar, email, moderator, livestreaming, recording, moderation, room } = req.body;

  try {
    const jwkPrivateKey = await getSigningKey();

    const token = await new SignJWT({
      aud: "jitsi",
      context: {
        user: {
          id,
          name,
          avatar,
          email,
          moderator: moderator.toString()
        },
        features: {
          livestreaming: livestreaming.toString(),
          recording: recording.toString(),
          moderation: moderation.toString()
        }
      },
      exp: Math.floor(Date.now() / 1000) + 86400,
      iss: "chat",
      nbf: Math.floor(Date.now() / 1000),
      room,
      sub: "vpaas-magic-cookie-098f04f2b4b64b6cbd0b6490cd5f2319"
    })
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'JWT',
        kid: 'vpaas-magic-cookie-098f04f2b4b64b6cbd0b6490cd5f2319/f682a6'
      })
      .sign(jwkPrivateKey);

    res.status(200).json({ token });
  } catch (error) {
    console.error('Error generating JWT:', error);
    res.status(500).send('Error generating JWT');
  }
});
