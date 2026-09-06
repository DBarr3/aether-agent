import type { AppContext } from "../context.js";
import { StaticTokenStore } from "../auth.js";
import { ApiClient } from "../transport.js";
import { requireMemory } from "./contract.js";

export function memoryApi(ctx: AppContext): ApiClient {
  const child = process.env["AETHER_PROJECT_MEMORY_TOKEN"];
  if (!child) return ctx.api;
  requireMemory(/^agt_[A-Za-z0-9_-]+$/.test(child), "authentication_required");
  return new ApiClient(ctx.cfg.baseUrl, new StaticTokenStore(child));
}
