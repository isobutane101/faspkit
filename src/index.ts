import { createFasp, debugCapability, sendSigned, Capability } from "./server.js";

export * from "./crypto.js";
export * from "./server.js";
export * from "./store.js";

/**
 * Sketch of a `link_preview` capability — one of the examples Mastodon names
 * as a good third-party FASP. No spec exists for this yet; the identifier and
 * shape below are a proposal, which is exactly the point: the spec repo invites
 * new capability specifications via PR.
 */
export function linkPreviewCapability(
  fetchPreview: (url: string) => Promise<Record<string, unknown>>,
): Capability {
  return {
    id: "link_preview",
    version: "0.1",
    register(router) {
      router.post("/link_preview/v0/previews", async (req, res) => {
        const urls: string[] = req.body?.urls ?? [];
        if (!Array.isArray(urls) || urls.length === 0) {
          return sendSigned(req, res, 422, { error: "urls array required" });
        }
        const previews = await Promise.all(
          urls.slice(0, 50).map(async (url) => {
            try {
              return { url, ...(await fetchPreview(url)) };
            } catch (err) {
              return { url, error: String(err) };
            }
          }),
        );
        sendSigned(req, res, 200, { previews });
      });
    },
  };
}

if (process.env.FASPKIT_RUN === "1") {
  const port = Number(process.env.PORT ?? 3000);
  const baseUrl = process.env.FASP_BASE_URL ?? `http://localhost:${port}`;
  const app = createFasp({
    name: process.env.FASP_NAME ?? "faspkit",
    baseUrl,
    privacyPolicy: [{ url: `${baseUrl}/privacy`, language: "en" }],
    capabilities: [debugCapability()],
  });
  app.listen(port, () => console.log(`faspkit listening on ${baseUrl}`));
}
