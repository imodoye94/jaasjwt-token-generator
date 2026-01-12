const functions = require('@google-cloud/functions-framework');
const { SignJWT, importPKCS8 } = require('jose');
const fs = require('fs');

const KEY_PATH = process.env.RS256_PRIVATE_KEY_PATH || '/run/secrets/jaaskey.pk';

let cachedKey = null;
async function getKey() {
  if (cachedKey) return cachedKey;
  const pem = fs.readFileSync(KEY_PATH, 'utf8');
  cachedKey = await importPKCS8(pem, 'RS256');
  return cachedKey;
}

functions.http('jaasjwt', async (req, res) => {
  const allowedOrigins = new Set(['https://backend.mediverse.ai', 'https://backend.hib.to']);
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
  }
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(204).send('');
  if (req.method !== 'POST') return res.status(405).end();

  const expectedApiKey = `Bearer ${process.env.APIKEY_FOR_VERIFYFRONTEND}`;
  if (req.headers.authorization !== expectedApiKey) return res.status(401).send('Unauthorized Request');

  const requiredFields = ['id','name','avatar','email','moderator','livestreaming','recording','moderation','room'];
  for (const f of requiredFields) {
    if (!Object.prototype.hasOwnProperty.call(req.body || {}, f)) return res.status(400).send(`Missing required parameter: ${f}`);
  }

  const { id, name, avatar, email, moderator, livestreaming, recording, moderation, room } = req.body;

  try {
    const jwkPrivateKey = await getKey();
    const token = await new SignJWT({
      aud: "jitsi",
      context: {
        user: { id, name, avatar, email, moderator: moderator.toString() },
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
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'vpaas-magic-cookie-098f04f2b4b64b6cbd0b6490cd5f2319/f682a6' })
    .sign(jwkPrivateKey);

    return res.status(200).json({ token });
  } catch (e) {
    console.error(e);
    return res.status(500).send('Error generating JWT');
  }
});
