/**
 * DEX Short-URL Installer Proxy (Cloudflare Workers ES Module)
 *
 * Deployment:
 * 1. Create a Cloudflare Worker (or `wrangler deploy`) using this script.
 * 2. Bind Custom Domain `dex.234579.xyz` to the Worker under Workers & Pages
 *    -> Settings -> Domains & Routes -> Add -> Custom Domain.
 * 3. Ensure `dex.234579.xyz` DNS is proxied by Cloudflare (orange cloud / managed by Workers).
 */

const UPSTREAM_URL = "https://raw.githubusercontent.com/stuinxo/dex/main/scripts/install.sh";
const CACHE_TTL_SECONDS = 300;
const RAW_PATHS = new Set(["/", "/dex", "/i", "/install.sh"]);
const ROLE_PATHS = new Map([
  ["/client", "client"],
  ["/server", "server"],
  ["/landing", "landing"],
  ["/relay", "relay"],
]);

function textResponse(body, status, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

export default {
  async fetch(request) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return textResponse("Method Not Allowed\n", 405, { Allow: "GET, HEAD" });
    }

    const { pathname } = new URL(request.url);
    const cleanPath = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
    const isRaw = RAW_PATHS.has(cleanPath);
    const role = ROLE_PATHS.get(cleanPath);

    if (!isRaw && !role) {
      return textResponse("Not Found\n", 404);
    }

    const upstream = await fetch(UPSTREAM_URL, {
      cf: {
        cacheTtl: CACHE_TTL_SECONDS,
        cacheEverything: true,
      },
    });

    if (!upstream.ok) {
      return textResponse(`Upstream fetch failed: ${upstream.status}\n`, 502);
    }

    let body = await upstream.text();
    if (role) {
      const patched = body.replace(
        /(^|\n)main "\$@"[ \t]*\r?\n?$/,
        `$1if [ "$#" -eq 0 ]; then main "${role}"; else main "$@"; fi\n`,
      );
      if (patched === body) {
        return textResponse("Upstream script entry point not found\n", 502);
      }
      body = patched;
    }

    const headers = {
      "Content-Type": "text/x-shellscript; charset=utf-8",
      "Cache-Control": `public, max-age=${CACHE_TTL_SECONDS}`,
      "X-Content-Type-Options": "nosniff",
    };

    return new Response(request.method === "HEAD" ? null : body, {
      status: 200,
      headers,
    });
  },
};
