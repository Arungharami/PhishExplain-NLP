import test from "node:test";import assert from "node:assert/strict";import {validateSpans,counts,metrics,scoreExamples,compareSpans} from "../lib/spans.js";
const txt="Act now: https://example.test",u={category:"urgency",text:"Act now",start:0,end:7},url={category:"url",text:"https://example.test",start:9,end:29};
test("exact offsets",()=>{assert.deepEqual(validateSpans(txt,[u])[0],u);assert.throws(()=>validateSpans(txt,[{...u,start:1}]))});
test("reject duplicates",()=>assert.throws(()=>validateSpans(txt,[u,u])));
test("count errors",()=>{assert.deepEqual(counts([u],[url]),{tp:0,fp:1,fn:1});assert.equal(metrics({tp:1,fp:1,fn:0}).f1,2/3)});
test("reviewed data score",()=>{const r=scoreExamples([{id:"1",text:txt,review_status:"REVIEWED",gold_spans:[u],baseline_spans:[u]}],"baseline_spans");assert.equal(r.micro.f1,1)});
test("unreviewed fail closed",()=>assert.throws(()=>scoreExamples([{text:txt,review_status:"UNREVIEWED",gold_spans:[],baseline_spans:[]}],"baseline_spans")));
test("disagreements",()=>assert.equal(compareSpans([u],[url]).only_baseline.length,1));
test("Unicode UTF-16 offset",()=>{const t="😀 act now";assert.equal(validateSpans(t,[{category:"urgency",text:"act now",start:3,end:10}]).length,1)});
