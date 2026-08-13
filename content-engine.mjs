import "dotenv/config"; import fs from "fs";
const KEY=process.env.ANTHROPIC_SUPPORT_KEY, SECRET=process.env.BASE44_SHARED_SECRET, BASE="http://localhost:3001", OWNER="danijel.muranovic@gmail.com";
const hdr={"Content-Type":"application/json","x-base44-auth":SECRET};
const TARGETS=["https://link-engage.lovable.app","https://aureon-nexus.lovable.app",
 "https://remontadasports.com","https://wordshieldpro.base44.app","https://concrete-cadence-vault.base44.app",
 "https://studypaw.base44.app","https://life-story-os.base44.app","https://tryeyeflow.com","https://natty-dream-20.lovable.app"
];
async function drain(res,on){const rd=res.body.getReader(),dec=new TextDecoder();let b="";for(;;){const{done,value}=await rd.read();if(done)break;b+=dec.decode(value,{stream:true});let i;while((i=b.indexOf("\n\n"))>=0){const s=b.slice(0,i);b=b.slice(i+2);const l=s.split("\n").find(x=>x.startsWith("data:"));if(l){try{on(JSON.parse(l.slice(5).trim()))}catch{}}}}}
const out=[];
for(const url of TARGETS){
  const rec={url,ok:false};
  try{
    let appId=null,pages=0;
    const lr=await fetch(BASE+"/api/learn",{method:"POST",headers:hdr,body:JSON.stringify({url,userEmail:OWNER,apiKey:KEY})});
    await drain(lr,ev=>{if(ev.appId)appId=ev.appId; if(ev.map&&ev.map.pages)pages=ev.map.pages.length; if(typeof ev.pagesCrawled==="number")pages=ev.pagesCrawled;});
    rec.appId=appId; rec.pages=pages;
    if(!appId){ rec.error="learn failed"; out.push(rec); fs.writeFileSync("content-engine-results.json",JSON.stringify(out,null,2)); console.log("XX",url,"learn failed"); continue; }
    const sr=await fetch(BASE+"/api/security/api-intercept",{method:"POST",headers:hdr,body:JSON.stringify({userEmail:OWNER,appId,apiKey:KEY,userA:{name:"A",email:"",password:""},userB:{name:"B",email:"",password:""},mode:"read-only"})});
    const j=await sr.json();
    const R=j.results||[];
    const vulns=R.filter(r=>r.verdict==="VULNERABLE");
    const susp=R.filter(r=>r.verdict==="SUSPICIOUS"||r.verdict==="POTENTIAL_VULNERABILITY");
    rec.ok=true; rec.totalTests=j.totalTests; rec.vulns=vulns.length; rec.suspicious=susp.length;
    rec.secrets=R.filter(r=>r.type==="secret_exposure"&&r.verdict==="VULNERABLE").map(s=>s.test);
    rec.topFindings=[...vulns,...susp].slice(0,8).map(r=>({sev:r.severity||r.verdict,test:r.test||r.type,note:(r.note||"").slice(0,110)}));
    out.push(rec); fs.writeFileSync("content-engine-results.json",JSON.stringify(out,null,2));
    console.log("OK",url,"| pages:",pages,"| vulns:",vulns.length,"| suspicious:",susp.length,"| secrets:",rec.secrets.join(",")||"none");
  }catch(e){ rec.error=String(e.message||e).slice(0,120); out.push(rec); fs.writeFileSync("content-engine-results.json",JSON.stringify(out,null,2)); console.log("ERR",url,rec.error); }
}
console.log("\n=== DONE",out.length,"apps ===");
