import type { AppContext } from "../context.js";
import { projectStatus } from "../../commands/project_memory.js";
import { validateManifest, validateReceipt } from "./contract.js";
import { memoryPath } from "./sync.js";
import { memoryApi } from "./network.js";

/** Host-generated status. Model text is never an input to this renderer. */
export async function memoryFooter(ctx: AppContext): Promise<string> {
  if (process.env["AETHER_PROJECT_MEMORY_ENABLED"] === "0") return "Memory  disabled by project policy";
  const result = projectStatus(ctx);
  if (result["state"] === "local" && typeof result["local_head"] === "string") return `Memory  local ${result["local_head"]} — run aether -m push`;
  if (result["state"] === "synchronized" && result["receipt"] && typeof result["project_id"] === "string" && typeof result["remote_head"] === "string") {
    // Local files are not an authority for a trusted remote-success footer.
    // Re-read the exact immutable receipt over authenticated transport.
    try {
      const value = await memoryApi(ctx).getJson(memoryPath(result["project_id"], `commits/${result["remote_head"]}`), undefined, 5000) as { manifest: unknown; receipt: unknown };
      validateManifest(value.manifest, result["project_id"]);
      if (value.manifest.commit_id !== result["remote_head"]) throw new Error("receipt mismatch");
      validateReceipt(value.receipt, value.manifest, Number(result["revision"]));
      return `Memory  unchanged · pushed ${value.manifest.commit_id} · revision ${result["revision"]}`;
    } catch { return "Memory  unchanged (last server receipt could not be verified)"; }
  }
  if (result["state"] === "dirty") return "Memory  not committed (staged changes)";
  if (result["state"] === "conflicted") return "Memory  conflicted — local commits preserved; run aether -m reconcile";
  return "Memory  not committed";
}
