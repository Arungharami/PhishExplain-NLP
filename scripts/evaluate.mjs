#!/usr/bin/env node
// Exact held-out benchmark evaluation. Will refuse partial, unreviewed, or ungrounded evidence.
import {readFileSync,writeFileSync} from "node:fs";
import {createHash} from "node:crypto";
import {validateSpans,scoreExamples,counts} from "../lib/spans.js";
import {extractSignals} from "../engine.js";
const sha=s=>createHash("sha256").update(s).digest("hex");
const key=s=>s.category+":"+s.start+":"+s.end;
function main(){
 const source=process.argv[2],target=process.argv[3];if(!source){console.error("Usage: node scripts/evaluate.mjs <human-reviewed-frozen-evidence.json> [results-output.json]");process.exit(2)}
 const raw=readFileSync(source,"utf8"),data=JSON.parse(raw),manifest=JSON.parse(readFileSync("data/split_manifest.json","utf8")),ds=JSON.parse(readFileSync("data/candidate_emails.json","utf8"));
 if(!Array.isArray(data.examples)||data.examples.length!==60)throw Error("Frozen evidence must contain exactly 60 original examples");
 const canonical=new Map(ds.examples.map(e=>[e.id,e])),seen=new Set(),expectedTest=new Set(manifest.test);
 const valid=[];
 for(const r of data.examples){
  const e=canonical.get(r.id);
  if(!e||e.text!==r.text||seen.has(r.id))throw Error("Modified, unknown, or duplicate example: "+r.id);
  seen.add(r.id);
  const split=expectedTest.has(r.id)?"test":"calibration";
  if(r.split!==split)throw Error("Split disagreement: "+r.id);
  if(split!=="test")continue;
  if(r.review_status!=="REVIEWED"||!r.reviewer?.trim())throw Error("Missing independent human review for held-out: "+r.id);
  const gold=validateSpans(r.text,r.gold_spans),baseline=validateSpans(r.text,r.baseline_spans),transformer=validateSpans(r.text,r.transformer_spans);
  const actual=extractSignals(r.text).categories.flatMap(c=>c.matches);
  if(baseline.map(key).sort().join("|")!==actual.map(key).sort().join("|"))throw Error("Baseline predictions differ from executable rule engine for "+r.id);
  valid.push({...r,gold_spans:gold,baseline_spans:baseline,transformer_spans:transformer});
 }
 if(seen.size!==60||valid.length!==40)throw Error("Not all 60 records present or 40 test records reviewed");
 if(!data.transformer_run||typeof data.transformer_run.model!=="string"||typeof data.transformer_run.prompt_version!=="string"||typeof data.transformer_run.executed_at!=="string")throw Error("Transformer provenance manifest missing (model, prompt_version, executed_at)");
 const classic=scoreExamples(valid,"baseline_spans"),llm=scoreExamples(valid,"transformer_spans");
 const errors=[];for(const row of valid){for(const [method,pred] of [["baseline",row.baseline_spans],["transformer",row.transformer_spans]]){const c=counts(row.gold_spans,pred);if(c.fp||c.fn)errors.push({id:row.id,method,...c,gold_spans:row.gold_spans,predicted_spans:pred,author_explanation:"PENDING HUMAN ERROR ANALYSIS"})}}
 const report={status:"CALCULATED_FROM_SUPPLIED_EVIDENCE",scope:"held-out test only",date_utc:new Date().toISOString(),source_sha256:sha(raw),corpus_version:ds.version,split_version:manifest.version,n_test:valid.length,transformer_run:data.transformer_run,primary_metric:"exact label + UTF-16 span match, micro-F1",baseline:classic,transformer:llm,observed_error_instances:errors.length,errors,limitations:["Transformer provenance must be independently checked against saved provider responses","Author gold labels are single-reviewer and require personal verification","Synthetic email benchmark limits external validity"]};
 if(target)writeFileSync(target,JSON.stringify(report,null,2)+"\n");
 console.log(JSON.stringify({...report,errors:errors.slice(0,6)},null,2));
}
try{main()}catch(err){console.error("Evaluation refused: "+err.message);process.exit(1)}
