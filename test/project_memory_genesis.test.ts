import test from "node:test";
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,realpathSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {scanProjectTree,type GenesisPolicy} from "../src/core/project_memory_genesis.js";

const policy=JSON.parse(readFileSync(new URL("../../test/fixtures/genesis-policy.json",import.meta.url),"utf8")) as GenesisPolicy;
test("local genesis reads the exact committed tree and nested ignore policy without scanning dirty contents",()=>{
  const root=realpathSync(mkdtempSync(join(tmpdir(),"memory-genesis-test-")));
  const git=(...args:string[])=>execFileSync("git",["-C",root,...args],{encoding:"utf8",windowsHide:true}).trim();
  try {
    git("init","--quiet");
    mkdirSync(join(root,"src"));mkdirSync(join(root,"excluded"));
    writeFileSync(join(root,".gitignore"),"*.txt\n!keep.txt\nexcluded/\n");
    writeFileSync(join(root,"src",".gitignore"),"!visible.txt\n");
    for(const file of ["README.md","keep.txt","ignored.txt","logo.png",".env","src/visible.txt","src/hidden.txt","excluded/readme.md"]) writeFileSync(join(root,file),"fixture");
    git("add","--all","--force");
    git("-c","user.name=Test","-c","user.email=fixture@example.invalid","commit","--quiet","-m","fixture");
    const sha=git("rev-parse","HEAD"),tree=git("rev-parse","HEAD^{tree}");
    // Current working-tree ignore edits must not alter the canonical scan.
    writeFileSync(join(root,".gitignore"),"");
    writeFileSync(join(root,"dirty-only.ts"),"uncommitted source must not be read");
    const graph=scanProjectTree(root,"prj_0123456789abcdef","pgraph_"+"a".repeat(32),"123",sha,tree,policy);
    const paths=graph.nodes.map(x=>x["label"]);
    for(const included of ["README.md","keep.txt","src/visible.txt"]) assert.ok(paths.includes(included),included);
    for(const excluded of ["ignored.txt","logo.png",".env","src/hidden.txt","excluded/readme.md","dirty-only.ts"]) assert.ok(!paths.includes(excluded),excluded);
    assert.equal(graph.source_tree_sha,tree);assert.equal(graph.partial,false);
    assert.throws(()=>scanProjectTree(root,graph.project_id,graph.graph_id,"123",sha,"f".repeat(40),policy),/source_mismatch/);
  } finally {rmSync(root,{recursive:true,force:true});}
});
