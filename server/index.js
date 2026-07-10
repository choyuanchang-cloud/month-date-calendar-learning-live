const INDEX_PATH = "/index.html";

function isPageRequest(request) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return false;
  }

  return request.headers.get("accept")?.includes("text/html") ?? false;
}

export default {
  async fetch(request, env) {
    const assetResponse = await env.ASSETS.fetch(request);

    if (assetResponse.status !== 404 || !isPageRequest(request)) {
      return assetResponse;
    }

    const indexUrl = new URL(INDEX_PATH, request.url);
    return env.ASSETS.fetch(new Request(indexUrl, request));
  },
};
