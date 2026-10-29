// Gloway Compliance API — deploy only after configuring secrets, D1 and Cloudflare Access.
// Fail closed: no public intake without Turnstile; no admin data without verified Access JWT.
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff",...headers}});
const clean=(v,max)=>typeof v==="string"&&v.trim().length>0&&v.trim().length<=max?v.trim():null;
const allowedServices=new Set(["New FDA food facility registration","Biennial renewal","Update an existing registration","Understand whether my facility needs registration","U.S. agent coordination"]);
const stages=new Set(["new_request","information_review","scope_payment","registration_coordination","confirmation_followup","renewal_monitoring"]);
function cors(request,env){const origin=request.headers.get("Origin");return origin===env.ALLOWED_ORIGIN?{"access-control-allow-origin":origin,"vary":"Origin","access-control-allow-methods":"POST,GET,PATCH,OPTIONS","access-control-allow-headers":"Content-Type,CF-Access-Jwt-Assertion"}:{}}
function bytes64url(input){const s=input.replace(/-/g,"+").replace(/_/g,"/");return Uint8Array.from(atob(s+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))}
function jwtPart(input){return JSON.parse(new TextDecoder().decode(bytes64url(input)))}
async function accessUser(request,env){
 const token=request.headers.get("CF-Access-Jwt-Assertion");if(!token||!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD||!env.ADMIN_EMAILS)return null;
 const parts=token.split(".");if(parts.length!==3)return null;
 let head,claims;try{head=jwtPart(parts[0]);claims=jwtPart(parts[1])}catch{return null}
 if(head.alg!=="RS256"||!head.kid||claims.aud!==env.ACCESS_AUD&&!(Array.isArray(claims.aud)&&claims.aud.includes(env.ACCESS_AUD)))return null;
 const domain=env.ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//,"").replace(/\/$/,"");
 if(!/^[a-z0-9.-]+\.cloudflareaccess\.com$/.test(domain)||claims.iss!==`https://${domain}`)return null;
 const now=Math.floor(Date.now()/1000);if(!claims.exp||claims.exp<=now||!claims.iat||claims.iat>now+60)return null;
 const certs=await fetch(`https://${domain}/cdn-cgi/access/certs`);if(!certs.ok)return null;
 const {keys}=await certs.json();const jwk=keys?.find(k=>k.kid===head.kid&&k.kty==="RSA");if(!jwk)return null;
 const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
 const valid=await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,bytes64url(parts[2]),new TextEncoder().encode(parts[0]+"."+parts[1]));if(!valid)return null;
 const email=typeof claims.email==="string"?claims.email.toLowerCase():"";
 const allow=env.ADMIN_EMAILS.split(",").map(x=>x.trim().toLowerCase()).filter(Boolean);
 return allow.includes(email)?email:null;
}
async function verifyTurnstile(token,request,env){if(!env.TURNSTILE_SECRET||!token)return false;const body=new URLSearchParams({secret:env.TURNSTILE_SECRET,response:token});const ip=request.headers.get("CF-Connecting-IP");if(ip)body.set("remoteip",ip);const r=await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify",{method:"POST",body});if(!r.ok)return false;const v=await r.json();return v.success===true&&(!v.hostname||v.hostname===new URL(env.ALLOWED_ORIGIN).hostname)}
export default {async fetch(request,env){
 const url=new URL(request.url),headers=cors(request,env),origin=request.headers.get("Origin");
 if(url.pathname==="/api/health"&&request.method==="GET")return json({status:"ok",service:"gloway-compliance-api"});
 if(!env.DB||!env.ALLOWED_ORIGIN)return json({error:"Service not configured"},503);
 if(request.method==="OPTIONS")return origin===env.ALLOWED_ORIGIN?new Response(null,{status:204,headers}):json({error:"Origin denied"},403);
 if(origin&&origin!==env.ALLOWED_ORIGIN)return json({error:"Origin denied"},403);
 try{
 if(url.pathname==="/api/applications"&&request.method==="POST"){
  if(request.headers.get("content-type")?.split(";")[0]!=="application/json")return json({error:"JSON required"},415,headers);
  if(Number(request.headers.get("content-length")||0)>12000)return json({error:"Request too large"},413,headers);
  const raw=await request.text();if(raw.length>12000)return json({error:"Request too large"},413,headers);
  const p=JSON.parse(raw);if(p.website)return json({error:"Request rejected"},400,headers);
  const business=clean(p.business,160),country=clean(p.country,80),contact=clean(p.contact,120),email=clean(p.email,180),service=clean(p.service,120),notes=typeof p.notes==="string"&&p.notes.length<=1000?p.notes.trim():"";
  if(!business||!country||!contact||!email||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!allowedServices.has(service)||p.consent!==true)return json({error:"Check required fields and consent"},400,headers);
  if(!await verifyTurnstile(p.turnstileToken,request,env))return json({error:"Verification failed"},403,headers);
  const id=crypto.randomUUID(),reference="GLC-"+id.slice(0,8).toUpperCase();
  await env.DB.prepare("INSERT INTO applications (id,reference,business,country,contact,email,service,notes,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)").bind(id,reference,business,country,contact,email,service,notes,"new_request",new Date().toISOString(),new Date().toISOString()).run();
  return json({reference,status:"new_request",message:"Request received. Keep this reference for follow-up."},201,headers);
 }
 if(url.pathname==="/api/admin/applications"&&request.method==="GET"){
  const user=await accessUser(request,env);if(!user)return json({error:"Unauthorized"},401,headers);
  const result=await env.DB.prepare("SELECT reference,business,country,contact,email,service,status,created_at,updated_at FROM applications ORDER BY created_at DESC LIMIT 100").all();
  return json({applications:result.results},200,headers);
 }
 const match=url.pathname.match(/^\/api\/admin\/applications\/([a-f0-9-]{36})\/status$/);
 if(match&&request.method==="PATCH"){
  const user=await accessUser(request,env);if(!user)return json({error:"Unauthorized"},401,headers);
  const p=await request.json();if(!stages.has(p.status))return json({error:"Invalid stage"},400,headers);
  const result=await env.DB.prepare("UPDATE applications SET status=?,updated_at=? WHERE id=?").bind(p.status,new Date().toISOString(),match[1]).run();
  return json({updated:result.meta.changes===1},result.meta.changes===1?200:404,headers);
 }
 return json({error:"Not found"},404,headers);
 }catch(e){console.error("API request failed",e instanceof Error?e.name:"unknown");return json({error:"Unable to process request"},500,headers)}
}};
