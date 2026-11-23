export const LABELS=Object.freeze(["url","urgency","credential"]);
export function validateSpans(text,spans) {
 if(typeof text!=="string"||!Array.isArray(spans)||spans.length>150)throw Error("Invalid input");
 const found=new Set();
 return spans.map(s=>{
  if(!s||!LABELS.includes(s.category)||!Number.isSafeInteger(s.start)||!Number.isSafeInteger(s.end)||s.start<0||s.end<=s.start||s.end>text.length||typeof s.text!=="string"||s.text!==text.slice(s.start,s.end))throw Error("Ungrounded span");
  const key=s.category+":"+s.start+":"+s.end;if(found.has(key))throw Error("Duplicate span");found.add(key);
  return {category:s.category,text:s.text,start:s.start,end:s.end,...(typeof s.rule==="string"?{rule:s.rule}:{})};
 }).sort((a,b)=>a.start-b.start||a.end-b.end)
}
export function counts(gold,pred){const key=s=>s.category+":"+s.start+":"+s.end;const g=new Set(gold.map(key)),p=new Set(pred.map(key));const tp=[...p].filter(k=>g.has(k)).length;return{tp,fp:p.size-tp,fn:g.size-tp}}
export function metrics({tp,fp,fn}){const precision=tp+fp?tp/(tp+fp):0,recall=tp+fn?tp/(tp+fn):0;return{tp,fp,fn,precision,recall,f1:precision+recall?2*precision*recall/(precision+recall):0}}
export function scoreExamples(rows,method){
 if(!Array.isArray(rows)||!rows.length)throw Error("No evaluation rows");
 let overall={tp:0,fp:0,fn:0},perfect=0;const per_category={};
 for(const row of rows){
  if(row.review_status!=="REVIEWED"||typeof row.text!=="string")throw Error("Unreviewed example");
  const g=validateSpans(row.text,row.gold_spans),p=validateSpans(row.text,row[method]);
  const c=counts(g,p);for(const k of ["tp","fp","fn"])overall[k]+=c[k];if(c.fp===0&&c.fn===0)perfect++;
 }
 for(const label of LABELS){const sum={tp:0,fp:0,fn:0};for(const row of rows){const c=counts(row.gold_spans.filter(x=>x.category===label),row[method].filter(x=>x.category===label));for(const k of ["tp","fp","fn"])sum[k]+=c[k]}per_category[label]=metrics(sum)}
 return {n:rows.length,micro:metrics(overall),macro_f1:LABELS.reduce((n,c)=>n+per_category[c].f1,0)/3,perfect_emails:perfect,per_category}
}
export function compareSpans(b,t){const key=x=>x.category+":"+x.start+":"+x.end;const a=new Set(b.map(key)),z=new Set(t.map(key));return{only_baseline:b.filter(x=>!z.has(key(x))),only_transformer:t.filter(x=>!a.has(key(x))),shared:b.filter(x=>z.has(key(x)))}}
