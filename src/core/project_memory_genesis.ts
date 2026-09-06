/** Consented local Git-tree scanner. Uncommitted contents never become facts. */
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, relative, isAbsolute, extname } from "node:path";
import { memoryDigest, parseGraph, ProjectMemoryError, type ProjectGraph, type Entity } from "./project_memory.js";

export interface GenesisPolicy {
  version:string;max_files:number;max_bytes:number;max_file_bytes:number;
  max_runtime_seconds:number;max_path_depth:number;excerpts:boolean;symlinks:boolean;
  denied_segments:string[];denied_suffixes:string[];
}

export function scanProjectTree(root:string, project:string, graphId:string, repositoryId:string,
  sha:string, tree:string, policy:GenesisPolicy):ProjectGraph {
  if (policy.version!=="apr-genesis/v1" || policy.excerpts || policy.symlinks ||
      !Number.isSafeInteger(policy.max_files) || policy.max_files<1 || policy.max_files>5000 ||
      !Number.isSafeInteger(policy.max_bytes) || policy.max_bytes>32_000_000 ||
      policy.max_file_bytes>1_000_000 || policy.max_runtime_seconds>180 || policy.max_path_depth>64 ||
      !Array.isArray(policy.denied_segments) || !Array.isArray(policy.denied_suffixes)) {
    throw new ProjectMemoryError("project_memory_policy_blocked");
  }
  const started=Date.now(), rootPath=realpathSync(root);
  // Git for Windows uses its POSIX null path, not Node's \\.\nul spelling.
  const emptyConfig="/dev/null";
  const env={...process.env,GIT_NO_REPLACE_OBJECTS:"1",GIT_CONFIG_NOSYSTEM:"1",GIT_CONFIG_GLOBAL:emptyConfig};
  const git=(cwd:string,args:string[],input?:string,maxBuffer=16_000_000):string=>{
    if (Date.now()-started>policy.max_runtime_seconds*1000) throw new ProjectMemoryError("project_memory_scan_timeout");
    try { return execFileSync("git",["-C",cwd,...args],{env,encoding:"utf8",input,timeout:15000,maxBuffer,windowsHide:true,stdio:["pipe","pipe","pipe"]}); }
    catch (error) {
      if (typeof error==="object" && error && "status" in error && error.status===1 && "stdout" in error && args.includes("check-ignore")) return String(error.stdout);
      throw new ProjectMemoryError("project_memory_source_unavailable");
    }
  };
  if (!/^[a-f0-9]{40}$/.test(sha) || git(rootPath,["rev-parse",`${sha}^{tree}`]).trim()!==tree) throw new ProjectMemoryError("project_memory_source_mismatch");
  const entries=git(rootPath,["ls-tree","-r","-z","-l","--full-tree",sha]).split("\0").filter(Boolean).map(line=>{
    const match=/^(\d{6}) (blob|commit) ([a-f0-9]{40})\s+(\d+|-)\t(.+)$/s.exec(line);
    if (!match || /^(?:\/|\\)|\.\.|[\\:\x00]/.test(match[5]!) || match[5]!.length>1024) throw new ProjectMemoryError("project_memory_source_mismatch");
    return {mode:match[1]!,type:match[2]!,sha:match[3]!,size:match[4]==="-"?0:Number(match[4]),path:match[5]!};
  }).sort((a,b)=>Buffer.compare(Buffer.from(a.path),Buffer.from(b.path)));
  const tempParent=realpathSync(tmpdir()), temp=mkdtempSync(join(tempParent,"aether-memory-tree-"));
  try {
    git(temp,["init","--quiet","--template="]);
    const ignored=(paths:string[])=>new Set(git(temp,["-c",`core.excludesFile=${emptyConfig}`,"-c","core.ignoreCase=false","check-ignore","--no-index","-z","--stdin"],paths.join("\0")+"\0").split("\0").filter(Boolean));
    const ignores=entries.filter(x=>x.path.split("/").pop()===".gitignore" && x.type==="blob" && x.mode!=="120000" && !x.path.split("/").some(p=>policy.denied_segments.includes(p)))
      .sort((a,b)=>a.path.split("/").length-b.path.split("/").length || Buffer.compare(Buffer.from(a.path),Buffer.from(b.path)));
    let rules=0;
    for (const item of ignores) {
      if (ignored([item.path]).has(item.path)) continue;
      if (++rules>32 || item.size>32768) throw new ProjectMemoryError("project_memory_policy_blocked");
      const path=join(temp,...item.path.split("/"));
      mkdirSync(dirname(path),{recursive:true,mode:0o700});
      writeFileSync(path,git(rootPath,["cat-file","blob",item.sha],undefined,65536),{mode:0o600});
    }
    const exclusions=entries.length ? ignored(entries.map(x=>x.path)) : new Set<string>();
    const policyDigest=memoryDigest(policy), evidence=memoryDigest({repository_id:repositoryId,commit:sha,tree});
    const provenance={producer:"git-tree-genesis",source:"repository_verified",evidence_refs:[evidence],policy_digest:policyDigest};
    const nodes=new Map<string,Entity>(), edges=new Map<string,Entity>(), reasons=new Set<string>();
    const add=(kind:string,path:string)=>{
      const id="node_"+memoryDigest({project,kind,locator:path}).slice(0,40);
      nodes.set(id,{id,kind,label:path,summary:"",schema_version:1,provenance,locator:{path,tree_sha:tree},first_seen_commit:null,last_seen_commit:null,confidence_milli:null,tombstone:false,visibility:"project",sensitivity:"internal"});
      return id;
    };
    const connect=(source:string,target:string)=>{
      const kind="contains", id="edge_"+memoryDigest({source,target,kind}).slice(0,40);
      edges.set(id,{id,source,target,kind,schema_version:1,provenance,tombstone:false,visibility:"project",sensitivity:"internal"});
    };
    const rootId=add("repository","repository");let inspected=0;
    for (const item of entries) {
      if (Date.now()-started>policy.max_runtime_seconds*1000) {reasons.add("scan_timeout");break;}
      const parts=item.path.split("/");
      if (parts.length>policy.max_path_depth) {reasons.add("path_depth_limit");continue;}
      if (item.mode==="120000" || parts.some(p=>policy.denied_segments.includes(p)) || policy.denied_suffixes.includes(extname(item.path).toLowerCase()) ||
          parts.some(p=>p.startsWith(".env") || /credential|secret|private[_-]?key|\.pem$|\.key$/i.test(p)) || exclusions.has(item.path)) continue;
      if (item.size>policy.max_file_bytes) {reasons.add("oversized_file");continue;}
      inspected+=item.size;
      if (nodes.size>=policy.max_files || inspected>policy.max_bytes) {reasons.add("scan_quota");break;}
      const node=add(item.type==="commit"?"dependency":"file",item.path);let parent=rootId;
      for(let depth=1;depth<parts.length;depth++) {const dir=add("directory",parts.slice(0,depth).join("/"));connect(parent,dir);parent=dir;}
      connect(parent,node);
    }
    return parseGraph({schema_version:"ProjectMemoryGraphV1",project_id:project,graph_id:graphId,source_sha:sha,source_tree_sha:tree,
      policy_digest:policyDigest,nodes:[...nodes.values()].sort((a,b)=>a.id<b.id?-1:1),edges:[...edges.values()].sort((a,b)=>a.id<b.id?-1:1),partial:reasons.size>0,truncation_reasons:[...reasons].sort()},project);
  } finally {
    const resolved=realpathSync(temp), rel=relative(tempParent,resolved);
    if (!isAbsolute(rel) && !rel.startsWith("..") && rel.startsWith("aether-memory-tree-")) rmSync(resolved,{recursive:true,force:true});
  }
}
