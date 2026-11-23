/**
 * PhishExplain Shield — browser-only, explainable email triage (beta).
 * No inbox integration, reputation lookups, malware scanning, or authenticated SPF/DKIM/DMARC verification.
 * Attention scores are fixed heuristic priorities, NOT probabilities, calibrated risk, or safety verdicts.
 */
import { extractSignals } from "./engine.js";

export const SHIELD_MAX_LENGTH = 30000;
export const SHIELD_VERSION = "shield-0.2.0";
const COMMON_SHORTENERS = new Set(["bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","tiny.cc","ow.ly","buff.ly"]);
const clamp=(n)=>Math.min(100,Math.max(0,Math.round(n)));
const unique=(a)=>[...new Set(a)];
function cleanHeaderValue(value){return String(value||"").replace(/[\r\n]+/g," ").trim()}
function firstHeader(headers,key){return headers[key]?.[0]||""}
function domainOf(address){
  const match=String(address||"").match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i);
  return match?match[1].toLowerCase().replace(/\.$/,""):null;
}
export function parseEmail(raw){
 if(typeof raw!=="string"||!raw.trim())throw new Error("Enter email text to scan");
 if(raw.length>SHIELD_MAX_LENGTH)throw new RangeError("Email exceeds 30,000 character local scanning limit");
 const lines=raw.replace(/\r\n/g,"\n").split("\n");
 const firstBlank=lines.indexOf("");
 const potential=firstBlank===-1?[]:lines.slice(0,firstBlank);
 const hasHeaderStart=potential.length>0&&potential.length<=100&&potential.some(line=>/^(from|to|reply-to|subject|date|authentication-results|return-path|received|content-type):/i.test(line));
 if(!hasHeaderStart)return {headers:{},body:raw,hasHeaders:false};
 const headers={};let key=null;
 for(const line of potential){
   const match=line.match(/^([A-Za-z][A-Za-z0-9-]{0,70}):\s*(.*)$/);
   if(match){key=match[1].toLowerCase();(headers[key]??=[]).push(match[2].trim())}
   else if(/^[ \t]/.test(line)&&key&&headers[key]?.length){headers[key][headers[key].length-1]+=" "+line.trim()}
   else return {headers:{},body:raw,hasHeaders:false};
 }
 return {headers,body:lines.slice(firstBlank+1).join("\n"),hasHeaders:true};
}
function makeFinding(id,label,detail,points,group,evidence){
 return {id,label,detail,points,group,evidence:evidence??null};
}
const domainIsIp=host=>/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)||host.startsWith("[");
const urlPattern=/\bhttps?:\/\/[^\s<>"'\u201c\u201d]+/gi;
export function inspectLinks(text){
 const candidates=[];
 for(const m of text.matchAll(urlPattern)){const clean=m[0].replace(/[)\].,;!?]+$/g,"");if(clean)candidates.push({value:clean,source:"visible URL",position:m.index})}
 // Static analysis only: never load or render arbitrary HTML.
 const anchor=/<a\b[^>]{0,1800}?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]{0,350}?)<\/a\s*>/gi;
 for(const m of text.matchAll(anchor)){
   const raw=(m[1]||m[2]||m[3]||"").trim();
   if(!/^https?:\/\//i.test(raw))continue;
   candidates.push({value:raw,source:"HTML href attribute",position:m.index,display:m[4].replace(/<[^>]*>/g,"").trim()});
 }
 const result=[],seen=new Set();
 for(const item of candidates.slice(0,100)){
   const key=item.value+"|"+item.position+"|"+item.source;if(seen.has(key))continue;seen.add(key);
   let parsed;try{parsed=new URL(item.value)}catch{continue}
   if(!["http:","https:"].includes(parsed.protocol))continue;
   const host=parsed.hostname.toLowerCase();const indicators=[];
   if(parsed.protocol==="http:")indicators.push(makeFinding("unencrypted-link","HTTP link","This URL uses HTTP, which does not provide HTTPS transport protection.",10,"link",host));
   if(parsed.username||parsed.password)indicators.push(makeFinding("url-userinfo","URL contains user information","An @-style authority can disguise the actual destination host.",30,"link",host));
   if(domainIsIp(host))indicators.push(makeFinding("ip-host","IP-address destination","The destination is a literal IP address rather than a recognizable domain.",24,"link",host));
   if(host.includes("xn--"))indicators.push(makeFinding("idn-host","Internationalized domain","Punycode in this hostname deserves closer visual verification; it is not inherently malicious.",12,"link",host));
   if(COMMON_SHORTENERS.has(host))indicators.push(makeFinding("shortened-url","Shortened destination","A known redirect-shortening service can obscure the final destination. No redirect was followed.",16,"link",host));
   if(host.split(".").length>=5)indicators.push(makeFinding("nested-subdomain","Long nested hostname","A long chain of subdomains can be visually misleading. Verify the entire hostname.",8,"link",host));
   if(host.split("-").length>5)indicators.push(makeFinding("hyphenated-host","Unusual hostname structure","This destination has numerous hyphen-separated segments.",7,"link",host));
   if(parsed.port&&!["80","443"].includes(parsed.port))indicators.push(makeFinding("custom-port","Nonstandard URL port","The destination specifies an explicit nonstandard network port.",9,"link",host));
   if(item.display){
     const textDomain=item.display.match(/\b(?:https?:\/\/)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b/i);
     if(textDomain){
       const shown=(textDomain[0].replace(/^https?:\/\//i,"")).toLowerCase();
       if(shown!==host){
         indicators.push(makeFinding("link-label-mismatch","Link text differs from destination","Visible anchor text names "+shown+" but the actual href targets "+host+".",30,"link",host));
       }
     }
   }
   result.push({url:item.value,hostname:host,protocol:parsed.protocol.slice(0,-1),source:item.source,position:item.position,display:item.display||null,indicators});
 }
 return result.slice(0,50);
}
export function analyzeEmail(raw){
 const parsed=parseEmail(raw);
 const from=cleanHeaderValue(firstHeader(parsed.headers,"from"));
 const replyTo=cleanHeaderValue(firstHeader(parsed.headers,"reply-to"));
 const fromDomain=domainOf(from),replyDomain=domainOf(replyTo);
 const subject=cleanHeaderValue(firstHeader(parsed.headers,"subject"));
 const auth=firstHeader(parsed.headers,"authentication-results");
 const findings=[];
 const lex=extractSignals(parsed.body);
 const urgency=lex.categories.find(x=>x.key==="urgency")?.matches||[];
 const credential=lex.categories.find(x=>x.key==="credential")?.matches||[];
 if(urgency.length)findings.push(makeFinding("urgency-language","Urgency or pressure wording","Matched "+urgency.length+" possible pressure phrase(s). Quoted or neutral uses can be false positives.",16,"language",urgency.slice(0,4).map(x=>x.text).join(" · ")));
 if(credential.length)findings.push(makeFinding("credential-request","Possible credential request","Matched "+credential.length+" phrase(s) requesting sign-in details. Verify context; negated safety warnings can match.",23,"language",credential.slice(0,4).map(x=>x.text).join(" · ")));
 if(urgency.length&&credential.length)findings.push(makeFinding("combined-pressure","Pressure plus credential language","Urgency and credential-related language appear together. This combination merits manual attention.",16,"combination",null));
 if(fromDomain&&replyDomain&&fromDomain!==replyDomain)findings.push(makeFinding("replyto-mismatch","Different From and Reply-To domains","Visible sender domain "+fromDomain+" differs from reply destination "+replyDomain+". This can be legitimate in delegated mail.",16,"sender",null));
 const links=inspectLinks(parsed.body);
 for(const row of links){for(const f of row.indicators)findings.push({...f,id:f.id+":"+row.position,evidence:row.hostname})}
 // A pasted Authentication-Results field does not establish real SPF/DKIM/DMARC; do not score it.
 const claimed={spf:null,dkim:null,dmarc:null};
 for(const k of Object.keys(claimed)){const match=auth.match(new RegExp("\\b"+k+"\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)\\b","i"));claimed[k]=match?match[1].toLowerCase():null}
 const attachmentFlag=/\bcontent-disposition\s*:\s*attachment\b/i.test(raw);
 const counts={url_mentions:links.length,urgency_phrases:urgency.length,credential_phrases:credential.length,link_indicators:links.reduce((n,r)=>n+r.indicators.length,0)};
 const rawPoints=findings.reduce((n,f)=>n+f.points,0);
 const score=clamp(rawPoints);
 const priority=score>=65?"High review priority":score>=30?"Elevated review priority":score>0?"Review suggested":"No listed indicators";
 const reasons=unique(findings.map(x=>x.label));
 const steps=score>=30?[
   "Do not click links, open attachments, or submit account details until you independently verify the request.",
   "Contact the sender using an address, official app, or phone number you already trust—not details in the email.",
   "Report suspicious messages through your email provider or organization's security workflow."
 ]:[
   "A low heuristic score does not establish that an email is safe.",
   "Verify unexpected requests through a known contact method before acting.",
   "Avoid entering passwords or codes from unsolicited email links."
 ];
 return {
   version:SHIELD_VERSION,engine:"local-browser-heuristics",timestamp:new Date().toISOString(),
   attention_score:score,score_type:"uncalibrated_attention_index_not_probability",
   priority,counts,findings,links,
   sender:{from:from||null,reply_to:replyTo||null,from_domain:fromDomain,reply_to_domain:replyDomain,subject:subject||null,headers_supplied:parsed.hasHeaders},
   authentication:{claimed,source:auth?"pasted_unverified_header":"not_provided",verified:false,note:"SPF/DKIM/DMARC are NOT validated here. Pasted Authentication-Results may be forged or outside the trusted receiving-server boundary."},
   attachment:{mentioned_in_raw_headers:attachmentFlag,scanned:false},
   extracted_language:{urgency,credential},
   recommended_actions:steps,
   limitations:["No provider authentication verification","No live URL reputation or redirect lookup","No malware/attachment scanning","No automatic blocking or inbox integration","Heuristic index has not been calibrated against an external email-security benchmark","Missing indicators do not imply safety"]
 };
}
export const SHIELD_SAMPLES={
 suspicious:"From: Account Service <notice@account-check.example>\nReply-To: help@support-alert.example\nSubject: Urgent account verification\n\nImmediate action required. Your account will be suspended within 24 hours. Please enter your password at http://192.0.2.45/login to keep access.",
 benign:"From: Research Office <office@university.example>\nSubject: Weekly meeting notes\n\nHello team,\nThe next meeting is Thursday at 2 PM. Here are the open meeting notes at https://docs.example/meeting. See you then.",
 awareness:"From: Security Training <training@university.example>\nSubject: Recognizing suspicious emails\n\nDo not share your password. If a message says act now, use a trusted official channel to confirm who sent it. This is a training example, not a password request.",
 html:"From: Account Support <team@updates.example>\nSubject: Account portal update\n\nPlease review <a href=\"https://verify-account.example/login\">https://official-portal.example</a> if you received this notice."
};
