export interface Env {
    AUD: string;
    JWT_SECRET: string;
  }
  
  function encodeBase64Url(str: string): string {
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }
  
  async function signJWT(header: any, payload: any, secretKey: Uint8Array): Promise<string> {
    const encoder = new TextEncoder();
    const data = encodeBase64Url(JSON.stringify(header)) + '.' + encodeBase64Url(JSON.stringify(payload));
    const signature = await crypto.subtle.sign(
      'HMAC',
      await crypto.subtle.importKey('raw', secretKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
      encoder.encode(data)
    );
  
    return `${encodeBase64Url(JSON.stringify(header))}.${encodeBase64Url(JSON.stringify(payload))}.${encodeBase64Url(String.fromCharCode(...new Uint8Array(signature)))}`;
  }
  
  export default {
    async fetch(request: Request, env: Env): Promise<Response> {
      const AUD = env.AUD;
      const JWT_SECRET = env.JWT_SECRET;
  
      if (!AUD || !JWT_SECRET) {
        return new Response(JSON.stringify({ error: 'Missing environment variables' }), {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          },
        });
      }
  
      const secretKey = new TextEncoder().encode(JWT_SECRET);
  
      const header = {
        alg: 'HS256',
        typ: 'JWT',
      };
  
      const payload = {
        aud: AUD,
        exp: Math.floor(Date.now() / 1000) + 300, // 5 minuti
        iat: Math.floor(Date.now() / 1000),
        iss: 'public-ai-stats',
      };
  
      const token = await signJWT(header, payload, secretKey);
  
      return new Response(JSON.stringify({ token }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
      });
    },
  };