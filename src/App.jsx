import React, { useState, useRef, useEffect, useMemo, useCallback } from "react";
import { checkBackend, api, apiPost } from "./api.js";
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, AreaChart, Area, ComposedChart, Cell, ScatterChart, Scatter,
  ZAxis, PieChart, Pie, ReferenceLine
} from "recharts";

/* ═══════════ THEMES ═══════════ */
const TH={
  light:{bg:"#EDF0F7",card:"#FFFFFF",cardBorder:"#E2E6EF",sidebar:"#FFFFFF",sidebarBorder:"#EDF0F7",sidebarActive:"#EEF0F8",topbar:"#FFFFFF",text:"#1A1D26",textSec:"#6B7185",textMuted:"#9CA3B8",primary:"#3B4A8A",primaryLight:"#EEF0F8",primaryGhost:"#F5F6FB",green:"#1B8553",greenBg:"#EAFAF1",red:"#D4380D",redBg:"#FFF1EC",orange:"#C67D1A",orangeBg:"#FFF8EC",blue:"#3B82F6",purple:"#8B5CF6",chartGrid:"#E8ECF3",inputBg:"#F5F6FA",inputBorder:"#DDE1EB",tableBg:"#F8F9FC",tableHover:"#EEF0F8",divider:"#EDF0F7",kpiIcon:"#EEF0F8",shadow:"rgba(59,74,138,0.08)"},
  dark:{bg:"#0F1117",card:"#1A1D2B",cardBorder:"#252837",sidebar:"#141620",sidebarBorder:"#1E2030",sidebarActive:"#1E2245",topbar:"#141620",text:"#E8EAF0",textSec:"#8B90A5",textMuted:"#555A70",primary:"#7B8FE0",primaryLight:"#1E2245",primaryGhost:"#161933",green:"#3DD68C",greenBg:"#0E2A1E",red:"#FF6B5A",redBg:"#2A1414",orange:"#FFB547",orangeBg:"#2A2010",blue:"#60A5FA",purple:"#A78BFA",chartGrid:"#252837",inputBg:"#1E2030",inputBorder:"#2A2D3E",tableBg:"#161828",tableHover:"#1E2245",divider:"#1E2030",kpiIcon:"#1E2245",shadow:"rgba(0,0,0,0.4)"},
};

/* ═══════════ EMPTY DEFAULTS ═══════════ */
const EMPTY_EM={sales:0,units:0,orders:0,refunds:0,advCost:0,shippingCost:0,refundCost:0,amazonFees:0,cogs:0,netProfit:0,estPayout:0,grossProfit:0,sessions:0,realAcos:0,pctRefunds:0,margin:0};

/* ═══════════ UTILS ═══════════ */
const $=n=>{if(n==null)return"—";return n<0?"-$"+Math.abs(n).toLocaleString("en-US",{maximumFractionDigits:0}):"$"+n.toLocaleString("en-US",{maximumFractionDigits:0})};
const $2=n=>{if(n==null)return"—";return n<0?"-$"+Math.abs(n).toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2}):"$"+n.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})};
const $s=n=>{if(n==null)return"—";const a=Math.abs(n),sg=n<0?"-":"";if(a>=1e6)return sg+"$"+(a/1e6).toFixed(1)+"M";if(a>=1e3)return sg+"$"+(a/1e3).toFixed(1)+"K";return sg+"$"+a};
const N=n=>n==null?"—":n.toLocaleString();
const mC=(m,t)=>m>10?t.green:m>0?t.orange:t.red;
const MS=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const TIPS={sales:"Total revenue from all sales",units:"Total units sold",refunds:"Refunded orders",advCost:"Total ad spend (PPC)",shippingCost:"FBA shipping fees",refundCost:"Cost of processing refunds",amazonFees:"Referral + FBA fees",cogs:"Cost of Goods Sold",netProfit:"Revenue − All Costs",estPayout:"Estimated Amazon payout",realAcos:"Ad Spend / Sales × 100%",pctRefunds:"Refunds / Orders × 100%",margin:"Net Profit / Revenue × 100%",sessions:"Product page views",gp:"SUM(grossProfit) from seller_board_sales",cr:"Orders / Sessions × 100%",ctr:"Clicks / Impressions × 100%",sellThrough:"Units Sold / (Sold + Ending Inventory)",doh:"Current Stock / Avg Daily Sales"};

/* ═══════════ BIDIRECTIONAL FILTER HOOK ═══════════ */
function useBidirectionalFilters(store,seller,brand,asinF,masterList){
  return useMemo(()=>{
    const ex=excl=>{let d=masterList;if(excl!=='store'&&store!=='All')d=d.filter(x=>x.st===store);if(excl!=='seller'&&seller!=='All')d=d.filter(x=>x.sl===seller);if(excl!=='brand'&&brand!=='All')d=d.filter(x=>x.b===brand);if(excl!=='asin'&&asinF!=='All')d=d.filter(x=>x.a===asinF);return d};
    return{stores:[...new Set(ex('store').map(x=>x.st))].filter(Boolean).sort(),sellers:[...new Set(ex('seller').map(x=>x.sl))].filter(Boolean).sort(),brands:[...new Set(ex('brand').map(x=>x.b))].filter(Boolean).sort(),asins:[...new Set(ex('asin').map(x=>x.a))].filter(Boolean).sort()};
  },[store,seller,brand,asinF,masterList]);
}

/* ═══════════ RESPONSIVE HOOK ═══════════ */
function useResp(){const[w,setW]=useState(window.innerWidth);useEffect(()=>{const h=()=>setW(window.innerWidth);window.addEventListener('resize',h);return()=>window.removeEventListener('resize',h)},[]);return{mob:w<768,tab:w>=768&&w<1024};}

/* ═══════════ SHARED COMPONENTS ═══════════ */
function Tip({text,t}){const[s,setS]=useState(false);return<span style={{position:"relative",display:"inline-flex",cursor:"help"}} onMouseEnter={()=>setS(true)} onMouseLeave={()=>setS(false)}><span style={{fontSize:10,color:t.textMuted,marginLeft:3}}>ⓘ</span>{s&&<div style={{position:"absolute",bottom:"calc(100% + 6px)",left:"50%",transform:"translateX(-50%)",background:t.text,color:t.bg,padding:"6px 10px",borderRadius:6,fontSize:10,whiteSpace:"nowrap",zIndex:999,boxShadow:"0 4px 12px rgba(0,0,0,.2)",fontWeight:500,maxWidth:280}}>{text}</div>}</span>}
function DateInput({label,value,onChange,t}){return<div style={{display:"flex",alignItems:"center",gap:4}}><span style={{fontSize:10,color:t.textMuted,fontWeight:600}}>{label}:</span><input type="date" value={value} onChange={e=>onChange(e.target.value)} style={{background:t.card,color:t.text,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"5px 8px",fontSize:11,fontWeight:500,cursor:"pointer"}}/></div>}

function PeriodBtns({onSelect,active,t,refDate}){
  const ref=refDate?new Date(refDate+"T00:00:00"):new Date();
  const fmt=d=>d.toISOString().slice(0,10);const now=fmt(ref);
  const dAgo=n=>{const d=new Date(ref);d.setDate(d.getDate()-n);return fmt(d)};
  const mS=(m=0)=>fmt(new Date(ref.getFullYear(),ref.getMonth()-m,1));
  const mE=(m=0)=>fmt(new Date(ref.getFullYear(),ref.getMonth()-m+1,0));
  const P=[["Today",now,now],["Yesterday",dAgo(1),dAgo(1)],["Last 7D",dAgo(6),now],["Last 14D",dAgo(13),now],["Last 30D",dAgo(29),now],["This Month",mS(0),now],["Last Month",mS(1),mE(1)],["Last 3M",mS(2),now],["YTD",ref.getFullYear()+"-01-01",now]];
  return<select value={active||""} onChange={e=>{const f=P.find(p=>p[0]===e.target.value);if(f)onSelect(f[1],f[2],f[0])}} style={{background:t.card,color:active?t.primary:t.text,border:"1px solid "+(active?t.primary:t.inputBorder),borderRadius:7,padding:"5px 10px",fontSize:11,fontWeight:600,cursor:"pointer"}}><option value="">⏱ Quick Select</option>{P.map(([l])=><option key={l} value={l}>{l}</option>)}</select>;
}
function ClearBtn({onClick,t}){return<button onClick={onClick} style={{padding:"4px 8px",borderRadius:6,border:"1px solid "+t.red,fontSize:10,cursor:"pointer",fontWeight:600,background:"transparent",color:t.red,whiteSpace:"nowrap"}}>✕ Clear</button>}
const Sel=({value,onChange,options,label,t,renderLabel})=><select value={value} onChange={e=>onChange(e.target.value)} style={{background:t.card,color:t.text,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"6px 10px",fontSize:11,fontWeight:500,cursor:"pointer"}}><option value="All">{label}</option>{options.map(o=><option key={o} value={o}>{renderLabel?renderLabel(o):o}</option>)}</select>;

function KpiCard({title,value,change,icon,t,tip}){return<div style={{background:t.card,borderRadius:12,padding:"16px 18px",border:"1px solid "+t.cardBorder}} onMouseEnter={e=>e.currentTarget.style.boxShadow="0 4px 20px "+t.shadow} onMouseLeave={e=>e.currentTarget.style.boxShadow="none"}><div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}><div style={{flex:1}}><div style={{fontSize:10,color:t.textMuted,textTransform:"uppercase",letterSpacing:.8,fontWeight:700,marginBottom:8}}>{title}{tip&&<Tip text={tip} t={t}/>}</div><div style={{fontSize:20,fontWeight:700,color:t.text,letterSpacing:-.3}}>{value}</div>{change!==undefined&&change!==null&&<div style={{display:"flex",alignItems:"center",gap:4,marginTop:6}}><span style={{fontSize:11,fontWeight:600,color:change>=0?t.green:t.red,background:change>=0?t.greenBg:t.redBg,padding:"2px 8px",borderRadius:10}}>{change>=0?"↑":"↓"} {Math.abs(change).toFixed(1)}%</span><span style={{fontSize:9,color:t.textMuted}}>vs prev</span></div>}</div><div style={{width:34,height:34,borderRadius:9,background:t.kpiIcon,display:"flex",alignItems:"center",justifyContent:"center",fontSize:15,flexShrink:0}}>{icon}</div></div></div>}

function PlanKpi({title,actual,plan,t,highlight,tip}){const isN=typeof actual==="number"&&typeof plan==="number";const gap=isN?actual-plan:null;const gc=gap!=null?(gap>=0?t.green:t.red):t.textMuted;return<div style={{background:highlight?t.primaryLight:t.card,borderRadius:12,padding:"16px 18px",border:highlight?"2px solid "+t.primary:"1px solid "+t.cardBorder}}><div style={{fontSize:10,color:highlight?t.primary:t.textMuted,textTransform:"uppercase",letterSpacing:.8,fontWeight:700,marginBottom:10}}>{highlight?"⭐ ":""}{title}{tip&&<Tip text={tip} t={t}/>}</div><div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:3}}><span style={{fontSize:11,color:t.textMuted}}>Actual</span><span style={{fontSize:highlight?22:18,fontWeight:700,color:highlight?t.primary:t.text}}>{isN?$(actual):actual}</span></div><div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline"}}><span style={{fontSize:11,color:t.textMuted}}>Plan</span><span style={{fontSize:12,fontWeight:600,color:t.textSec}}>{isN?$(plan):plan}</span></div><div style={{marginTop:10,padding:"7px 10px",borderRadius:7,background:t.primaryGhost,display:"flex",justifyContent:"space-between"}}><span style={{fontSize:10,color:t.textMuted}}>Gap</span><span style={{fontSize:12,fontWeight:700,color:gc}}>{gap!=null?$(gap):"—"}</span></div></div>}

const Sec=({title,icon,t,action,children})=><div style={{marginTop:20}}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}><div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:14}}>{icon}</span><span style={{fontSize:13,fontWeight:700,color:t.text}}>{title}</span></div>{action}</div>{children}</div>;
const Cd=({children,t,style:s})=><div style={{background:t.card,borderRadius:12,padding:16,border:"1px solid "+t.cardBorder,...s}}>{children}</div>;
const CT=({active,payload,label,t:th})=>{if(!active||!payload?.length)return null;const t=th||TH.light;return<div style={{background:t.card,border:"1px solid "+t.cardBorder,borderRadius:8,padding:"8px 12px",boxShadow:"0 4px 16px "+t.shadow}}><div style={{fontSize:10,color:t.textMuted,marginBottom:4,fontWeight:600}}>{label}</div>{payload.filter(p=>p.value!=null).map((p,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:5,fontSize:11,marginTop:2}}><div style={{width:7,height:7,borderRadius:4,background:p.color,flexShrink:0}}/><span style={{color:t.textSec}}>{p.name}:</span><span style={{fontWeight:700,color:p.color}}>{typeof p.value==="number"&&Math.abs(p.value)>999?$s(p.value):p.value?.toLocaleString?.()??p.value}</span></div>)}</div>};

function APG({actual,plan,t,isMoney=true,suffix="",reverse=false}){if(actual==null)return<div><div style={{fontSize:13,fontWeight:700,color:t.textMuted}}>—</div><div style={{fontSize:10,color:t.textMuted}}>Plan: {isMoney?$(plan):N(plan)+suffix}</div></div>;const gap=typeof actual==="number"?actual-plan:null;const gc=gap!=null?(reverse?(gap<=0?t.green:t.red):(gap>=0?t.green:t.red)):t.textMuted;const fA=isMoney?$(actual):(typeof actual==="number"?actual.toLocaleString():actual)+suffix;const fP=isMoney?$(plan):(typeof plan==="number"?plan.toLocaleString():plan)+suffix;const fG=gap!=null?(isMoney?$(gap):(gap>=0?"+":"")+gap.toLocaleString()+suffix):"—";return<div style={{lineHeight:1.5}}><div style={{fontSize:13,fontWeight:700,color:t.text}}>{fA}</div><div style={{fontSize:10,color:t.textMuted}}>Plan: {fP}</div><div style={{fontSize:10,fontWeight:600,color:gc}}>{fG}</div></div>}

/* ═══════════ GRADIENT CHART HELPER ═══════════ */
const ChartGrads=({t})=><defs><linearGradient id="gRv" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.primary} stopOpacity={0.15}/><stop offset="100%" stopColor={t.primary} stopOpacity={0}/></linearGradient><linearGradient id="gNp" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.green} stopOpacity={0.15}/><stop offset="100%" stopColor={t.green} stopOpacity={0}/></linearGradient></defs>;

function TrendChart({data,t,h=240,keys}){
  const k=keys||[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"},{dk:"netProfit",n:"Net Profit",c:t.green,g:"url(#gNp)"}];
  return<Cd t={t}><ResponsiveContainer width="100%" height={h}><ComposedChart data={data}><ChartGrads t={t}/><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="label" tick={{fill:t.textMuted,fontSize:9}} interval={Math.max(0,Math.floor(data.length/8))}/><YAxis tick={{fill:t.textMuted,fontSize:9}} tickFormatter={v=>$s(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/>{k.map(ki=><Area key={ki.dk} type="monotone" dataKey={ki.dk} name={ki.n} fill={ki.g||"none"} stroke={ki.c} strokeWidth={2}/>)}</ComposedChart></ResponsiveContainer></Cd>;
}

/* ═══════════ ALERTS ═══════════ */
function Alerts({alerts,t}){return<Cd t={t}><div style={{display:"flex",alignItems:"center",gap:6,marginBottom:10}}><span>⚠️</span><span style={{fontSize:12,fontWeight:700,color:t.orange}}>Alerts & Anomalies</span></div>{alerts.map((a,i)=><div key={i} style={{display:"flex",alignItems:"flex-start",gap:8,padding:"6px 0",borderTop:i?"1px solid "+t.divider:"none"}}><div style={{width:6,height:6,borderRadius:3,marginTop:5,background:a.s==="c"?t.red:a.s==="w"?t.orange:t.blue,flexShrink:0}}/><span style={{fontSize:11,color:t.textSec,lineHeight:1.5}}>{a.t}</span></div>)}</Cd>}

function genAlerts(fAsin,t,extra){
  const alerts=[];const neg=fAsin.filter(a=>a.n<0);const hiAcos=fAsin.filter(a=>a.ac>50);const top=[...fAsin].sort((a,b)=>b.n-a.n)[0];
  if(neg.length)alerts.push({s:"c",t:`${neg.length} ASINs with negative profit. Worst: ${neg[0]?.a} at ${$(neg[0]?.n)}`});
  if(hiAcos.length)alerts.push({s:"w",t:`${hiAcos.length} ASINs with ACoS >50%. Review ad spend.`});
  if(top)alerts.push({s:"i",t:`Top performer: ${top.a} (${top.b}) with ${$(top.n)} net profit`});
  if(extra)alerts.push(...extra);
  if(!alerts.length)alerts.push({s:"i",t:"All metrics within normal range."});
  return alerts;
}
function genShopAlerts(shops,t){const alerts=[];const poor=shops.filter(s=>s.m<0);const best=[...shops].sort((a,b)=>b.n-a.n)[0];if(poor.length)alerts.push({s:"c",t:`${poor.length} shops with negative margin: ${poor.map(s=>s.s).join(", ")}`});if(best)alerts.push({s:"i",t:`Top shop: ${best.s} with ${$(best.n)} net profit (${best.m.toFixed(1)}% margin)`});return alerts.length?alerts:[{s:"i",t:"All shops performing within normal range."}];}
function genSellerAlerts(sellers,t){const alerts=[];const neg=sellers.filter(s=>s.m<3);const best=[...sellers].sort((a,b)=>b.n-a.n)[0];if(neg.length)alerts.push({s:"w",t:`${neg.length} sellers with margin <3%: ${neg.map(s=>s.sl).join(", ")}`});if(best)alerts.push({s:"i",t:`Top seller: ${best.sl} with ${$(best.n)} net profit (${best.m.toFixed(1)}% margin)`});return alerts.length?alerts:[{s:"i",t:"All sellers performing well."}];}
function genOpsAlerts(fDaily,t){const alerts=[];const negDays=fDaily.filter(d=>d.netProfit<0);if(negDays.length>5)alerts.push({s:"w",t:`${negDays.length} days with negative NP in selected period`});const maxD=[...fDaily].sort((a,b)=>b.revenue-a.revenue)[0];if(maxD)alerts.push({s:"i",t:`Peak revenue day: ${maxD.label} at ${$(maxD.revenue)}`});return alerts.length?alerts:[{s:"i",t:"Daily operations within normal range."}];}
function genInvAlerts(shops){const a=[];const tFba=shops.reduce((s,x)=>s+x.fba,0);const crit=shops.reduce((s,x)=>s+x.crit,0);const lowSt=shops.filter(s=>s.st<2);const hiDoh=shops.filter(s=>s.doh>50);a.push({s:"i",t:`Total FBA stock: ${N(tFba)} units across ${shops.length} shops`});if(crit>100)a.push({s:"c",t:`${crit} critical SKUs need restocking`});else if(crit>0)a.push({s:"w",t:`${crit} critical SKUs — monitor closely`});if(lowSt.length)a.push({s:"w",t:`${lowSt.length} shops with sell-through <2%: ${lowSt.map(s=>s.s).join(", ")}`});if(hiDoh.length)a.push({s:"i",t:`${hiDoh.length} shops with >50 days of health: ${hiDoh.map(s=>s.s).join(", ")} — consider reducing orders`});return a;}

/* ═══════════ EXECUTIVE ═══════════ */
function ExecPage({t,fAsin,fShop,fDaily,em,sd,ed,prevEm,pctChg,mob}){
  const tR=fShop.reduce((s,x)=>s+x.r,0);
  const colors=[t.primary,"#6B7FD7","#9BA8E0","#E8618C",t.green,t.orange];
  const donut=fShop.slice(0,6).map((s,i)=>({name:s.s,value:s.r,fill:colors[i%6]}));
  if(fShop.length>6)donut.push({name:"Others",value:fShop.slice(6).reduce((s,x)=>s+x.r,0),fill:t.textMuted});
  const fmtD=d=>{try{return new Date(d+"T00:00:00").toLocaleDateString("en-US",{month:"short",day:"numeric",year:"numeric"})}catch{return d}};
  const ch=k=>prevEm?pctChg(em[k],prevEm[k]):undefined;
  const ChgBadge=({v})=>{if(v==null)return null;const c=v>=0?"#8CFFC1":"#FF9A8A";return<div style={{fontSize:8,fontWeight:600,color:c,marginTop:1}}>{v>=0?"↑":"↓"}{Math.abs(v).toFixed(1)}%</div>};
  const smItems=[{l:"Sales",v:$2(em.sales),c:ch("sales")},{l:"Orders",v:N(em.orders),c:ch("orders")},{l:"Units",v:N(em.units),c:ch("units")},{l:"Refunds",v:N(em.refunds),c:ch("refunds")},{l:"Adv. Cost",v:$2(em.advCost),c:ch("advCost")},{l:"Est. Payout",v:$2(em.estPayout),c:ch("estPayout")},{l:"Net Profit",v:$2(em.netProfit),c:ch("netProfit")}];
  return<div>
    <Cd t={t} style={{borderLeft:"4px solid "+t.primary,marginBottom:16,padding:"14px 18px"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
        <div><div style={{fontSize:12,fontWeight:800,color:t.text,letterSpacing:.5}}>SELLERBOARD SUMMARY</div><div style={{fontSize:10,color:t.textMuted,marginTop:2}}>{fmtD(sd)} — {fmtD(ed)}</div></div>
        {ch("sales")!=null&&<span style={{fontSize:10,fontWeight:600,color:ch("sales")>=0?t.green:t.red,background:ch("sales")>=0?t.greenBg:t.redBg,padding:"4px 12px",borderRadius:10}}>{ch("sales")>=0?"↑":"↓"} {Math.abs(ch("sales")).toFixed(1)}% vs prev period</span>}
      </div>
      <div style={{display:"grid",gridTemplateColumns:mob?"repeat(3,1fr)":"repeat(7,1fr)",gap:mob?10:6}}>
        {smItems.map((m,i)=><div key={i} style={{textAlign:"center",padding:"8px 4px",borderRadius:8,background:t.primaryGhost}}>
          <div style={{fontSize:9,color:t.textMuted,textTransform:"uppercase",fontWeight:700,letterSpacing:.5}}>{m.l}</div>
          <div style={{fontSize:mob?14:15,fontWeight:700,color:m.l==="Net Profit"?(em.netProfit>=0?t.green:t.red):t.text,marginTop:3}}>{m.v}</div>
          {m.c!=null&&<div style={{fontSize:9,fontWeight:600,color:m.c>=0?t.green:t.red,marginTop:2}}>{m.c>=0?"↑":"↓"}{Math.abs(m.c).toFixed(1)}%</div>}
        </div>)}
      </div>
    </Cd>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:14,marginBottom:16}}>
      <Cd t={t} style={{padding:14}}><div style={{fontSize:11,fontWeight:700,color:t.textMuted,textTransform:"uppercase",marginBottom:10}}>📊 Detailed Metrics</div><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><tbody>{[["Sales",$2(em.sales),TIPS.sales],["Units",N(em.units),TIPS.units],["Refunds",N(em.refunds),TIPS.refunds],["Ad Cost",$2(em.advCost),TIPS.advCost],["Shipping",$2(em.shippingCost),TIPS.shippingCost],["Refund Cost",$2(em.refundCost),TIPS.refundCost],["Amazon Fees",$2(em.amazonFees),TIPS.amazonFees],["COGS",$2(em.cogs),TIPS.cogs],["Net Profit",$2(em.netProfit),TIPS.netProfit],["Payout",$2(em.estPayout),TIPS.estPayout],["ACOS",(em.realAcos||0).toFixed(2)+"%",TIPS.realAcos],["% Refunds",(em.pctRefunds||0).toFixed(2)+"%",TIPS.pctRefunds],["Margin",(em.margin||0).toFixed(2)+"%",TIPS.margin],["Sessions",N(Math.round(em.sessions||0)),TIPS.sessions]].map(([l,v,tip],i)=><tr key={i} style={{borderBottom:"1px solid "+t.divider}}><td style={{padding:"6px 8px",color:t.textSec,fontWeight:500}}>{l}<Tip text={tip} t={t}/></td><td style={{padding:"6px 8px",textAlign:"right",fontWeight:700,color:t.text}}>{v}</td></tr>)}</tbody></table></Cd>
      <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:10}}><KpiCard title="Revenue" value={$(em.sales)} change={ch("sales")} icon="💰" t={t} tip={TIPS.sales}/><KpiCard title="Net Profit" value={$(em.netProfit)} change={ch("netProfit")} icon="📈" t={t} tip={TIPS.netProfit}/><KpiCard title="Margin" value={(em.margin||0).toFixed(2)+"%"} change={prevEm?em.margin-prevEm.margin:undefined} icon="🎯" t={t} tip={TIPS.margin}/><KpiCard title="Orders" value={N(em.orders)} change={ch("orders")} icon="🛒" t={t}/><KpiCard title="Sessions" value={N(Math.round(em.sessions||0))} change={ch("sessions")} icon="👁" t={t} tip={TIPS.sessions}/><KpiCard title="Ad Spend" value={$2(Math.abs(em.advCost||0))} change={ch("advCost")} icon="⚡" t={t} tip={TIPS.advCost}/></div>
    </div>
    <Sec title="Daily Trend" icon="📊" t={t}><TrendChart data={fDaily} t={t} h={260}/></Sec>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1.4fr .6fr",gap:14,marginTop:16}}>
      <Sec title="Revenue & NP by Shop" icon="🏪" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={Math.max(200,fShop.length*35)}><BarChart data={fShop} layout="vertical" margin={{left:90}} barSize={14}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis type="number" tick={{fill:t.textMuted,fontSize:10}} tickFormatter={v=>$s(v)}/><YAxis type="category" dataKey="s" tick={{fill:t.textSec,fontSize:10}} width={85}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar dataKey="r" name="Revenue" fill={t.primary} radius={[0,4,4,0]}/><Bar dataKey="n" name="Net Profit" radius={[0,4,4,0]}>{fShop.map((e,i)=><Cell key={i} fill={e.n>=0?t.green:t.red}/>)}</Bar></BarChart></ResponsiveContainer></Cd></Sec>
      <Sec title="Revenue Share" icon="🍩" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={200}><PieChart><Pie data={donut} innerRadius={55} outerRadius={80} dataKey="value" nameKey="name" cx="50%" cy="50%" paddingAngle={2} stroke="none">{donut.map((e,i)=><Cell key={i} fill={e.fill}/>)}</Pie><Tooltip/></PieChart></ResponsiveContainer><div style={{display:"flex",flexWrap:"wrap",gap:5,justifyContent:"center"}}>{donut.map((d,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:3,fontSize:9,color:t.textSec}}><div style={{width:7,height:7,borderRadius:2,background:d.fill}}/>{d.name}</div>)}</div></Cd></Sec>
    </div>
    <Sec title="ASIN Performance" icon="📋" t={t}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{["ASIN","Brand","Revenue","Net Profit","Margin%","Units","CR%","ACoS","ROAS"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=2?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fAsin.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontFamily:"monospace",fontSize:11,fontWeight:600,color:t.textSec,borderBottom:"1px solid "+t.divider}}>{r.a}</td><td style={{padding:"8px 12px",fontWeight:700,color:t.text,borderBottom:"1px solid "+t.divider}}>{r.b}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(1)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.cr}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ac<30?t.green:r.ac<50?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ac}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ro>3?t.green:r.ro>2?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ro.toFixed(2)}</td></tr>)}</tbody></table><div style={{padding:"6px 12px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider,position:"sticky",bottom:0,background:t.card}}>{fAsin.length} ASINs</div></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genAlerts([...fAsin],t,[{s:"i",t:`Showing ${fDaily.length} days (${fDaily[0]?.label||""} — ${fDaily[fDaily.length-1]?.label||""})`}])}/></div>
  </div>;
}

/* ═══════════ INVENTORY ═══════════ */
function InvPage({t,mob,invData,invShop,invTrend}){
  const d=invData||{};
  return<div>
    <Cd t={t} style={{padding:"10px 16px",marginBottom:14,borderLeft:"3px solid "+t.blue}}><div style={{fontSize:11,color:t.textSec}}>💡 Latest inventory snapshot. No time filter needed.</div></Cd>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(148px,1fr))",gap:12,marginBottom:16}}>
      <KpiCard title="FBA Stock" value={N(d.fbaStock||0)} icon="📦" t={t}/><KpiCard title="Available" value={N(d.availableInv||0)} icon="🗃" t={t}/><KpiCard title="Reserved" value={N(d.reserved||0)} icon="🔒" t={t}/><KpiCard title="Critical SKUs" value={N(d.criticalSkus||0)} icon="🚨" t={t}/><KpiCard title="Inbound" value={N(d.inbound||0)} icon="📥" t={t}/><KpiCard title="Avg Days Supply" value={Math.round(d.avgDaysOfSupply||0)} icon="📈" t={t} tip={TIPS.doh}/>
    </div>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:14}}>
      <Sec title="FBA Stock Trend" icon="📈" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={240}><AreaChart data={invTrend}><defs><linearGradient id="ig" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.primary} stopOpacity={.2}/><stop offset="100%" stopColor={t.primary} stopOpacity={0}/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="d" tick={{fill:t.textMuted,fontSize:9}}/><YAxis tick={{fill:t.textMuted,fontSize:9}} tickFormatter={N}/><Tooltip content={<CT t={t}/>}/><Area type="monotone" dataKey="v" name="FBA Stock" stroke={t.primary} fill="url(#ig)" strokeWidth={2}/></AreaChart></ResponsiveContainer></Cd></Sec>
      <Sec title="Sell-Through & Days of Health" icon="📊" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={240}><ComposedChart data={invShop}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="s" tick={{fill:t.textMuted,fontSize:9}} interval={0} angle={-20} textAnchor="end" height={50}/><YAxis yAxisId="l" tick={{fill:t.textMuted,fontSize:9}} unit="%"/><YAxis yAxisId="r" orientation="right" tick={{fill:t.textMuted,fontSize:9}} unit="d"/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar yAxisId="l" dataKey="st" name="Sell-Through %" fill={t.green} radius={[4,4,0,0]} fillOpacity={.7}/><Line yAxisId="r" type="monotone" dataKey="doh" name="Days of Health" stroke={t.orange} strokeWidth={2} dot={{r:3}}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    </div>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:14,marginTop:14}}>
      <Sec title="Inventory Aging" icon="📊" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={220}><BarChart data={[{name:"0-90d",v:d.age0_90||0},{name:"91-180d",v:d.age91_180||0},{name:"181-270d",v:d.age181_270||0},{name:"271-365d",v:d.age271_365||0},{name:"365d+",v:d.age365plus||0}]}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="name" tick={{fill:t.textMuted,fontSize:9}}/><YAxis tick={{fill:t.textMuted,fontSize:9}} tickFormatter={N}/><Tooltip content={<CT t={t}/>}/><Bar dataKey="v" name="Units" fill={t.orange} radius={[4,4,0,0]}/></BarChart></ResponsiveContainer></Cd></Sec>
      <Sec title="FBA Stock by Shop" icon="📦" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={220}><BarChart data={[...invShop].sort((a,b)=>b.fba-a.fba)} layout="vertical" margin={{left:85}}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis type="number" tick={{fill:t.textMuted,fontSize:9}} tickFormatter={N}/><YAxis type="category" dataKey="s" tick={{fill:t.textSec,fontSize:9}} width={80}/><Tooltip content={<CT t={t}/>}/><Bar dataKey="fba" name="FBA Stock" fill={t.primary} radius={[0,4,4,0]}/></BarChart></ResponsiveContainer></Cd></Sec>
    </div>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genInvAlerts(invShop)}/></div>
  </div>;
}

/* ═══════════ ASIN PLAN ═══════════ */
function PlanPage({t,planKpi,monthPlanData,asinPlanBkData,seller,brand,asinF}){
  const fPlanBk=asinPlanBkData||[];
  const isF=(seller&&seller!=="All")||(brand&&brand!=="All")||(asinF&&asinF!=="All");
  const[trendMetric,setTrendMetric]=useState("gp");
  const[kpiMonth,setKpiMonth]=useState("All");
  const[tblMonth,setTblMonth]=useState("All");
  const metrics=[{k:"gp",l:"Gross Profit"},{k:"rv",l:"Revenue"},{k:"ad",l:"Ads Spend"},{k:"un",l:"Units"},{k:"se",l:"Sessions"},{k:"im",l:"Impressions"},{k:"cr",l:"Conv. Rate"},{k:"ct",l:"Click-Through Rate"}];
  const mK={gp:{a:"gpa",p:"gpp"},rv:{a:"ra",p:"rp"},ad:{a:"aa",p:"ap"},un:{a:"ua",p:"up"},se:{a:"sa",p:"sp"},im:{a:"ia",p:"ip"},cr:{a:"cra",p:"crp"},ct:{a:"cta",p:"ctp"}};
  
  const mpd=monthPlanData||[];
  const hasData=mpd.some(m=>(m.gpa||0)+(m.gpp||0)+(m.ra||0)+(m.rp||0)>0)||fPlanBk.length>0;
  const trendData=mpd.map(m=>{const ak=mK[trendMetric].a,pk2=mK[trendMetric].p;return{m:m.m,Actual:m[ak],Plan:m[pk2]}});
  const isCur=["gp","rv","ad"].includes(trendMetric);const isPct=["cr","ct"].includes(trendMetric);
  const kpiData=useMemo(()=>{
    const pk=planKpi||{gp:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}};
    if(kpiMonth==="All")return pk;
    const mi=MS.indexOf(kpiMonth);const m=mpd[mi];if(!m)return pk;
    return{gp:{a:m.gpa,p:m.gpp},rv:{a:m.ra,p:m.rp},ad:{a:m.aa,p:m.ap},un:{a:m.ua,p:m.up},se:{a:m.sa,p:m.sp},im:{a:m.ia,p:m.ip},cr:{a:m.cra,p:m.crp},ct:{a:m.cta,p:m.ctp}};
  },[kpiMonth,planKpi,mpd]);
  const THD=["Month","⭐ GP","REVENUE","ADS","UNITS","SESSIONS","IMP","CR","CTR"];
  const AHDL=["ASIN","Brand","⭐ GP","REVENUE","ADS","UNITS","SESSIONS","IMP","CR","CTR"];
  return<div>
    {!hasData&&<div style={{padding:24,textAlign:"center",color:t.textMuted,fontSize:13,background:t.card,borderRadius:12,border:"1px solid "+t.cardBorder,marginBottom:16}}>📋 No plan data found for this year/filter combination. Try selecting a different year or adjusting filters.</div>}
    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:12}}><span style={{fontSize:11,color:t.textMuted,fontWeight:600}}>KPI Month:</span><Sel value={kpiMonth} onChange={setKpiMonth} options={MS} label="All Months" t={t}/></div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:12,marginBottom:12}}><PlanKpi title="Gross Profit" actual={kpiData.gp.a} plan={kpiData.gp.p} t={t} highlight tip={TIPS.gp}/><PlanKpi title="Revenue" actual={kpiData.rv.a} plan={kpiData.rv.p} t={t}/><PlanKpi title="Ads Spend" actual={kpiData.ad.a} plan={kpiData.ad.p} t={t}/><PlanKpi title="Units" actual={kpiData.un.a} plan={kpiData.un.p} t={t}/></div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:12,marginBottom:16}}><PlanKpi title="Sessions" actual={kpiData.se.a} plan={kpiData.se.p} t={t}/><PlanKpi title="Impressions" actual={kpiData.im.a} plan={kpiData.im.p} t={t}/><PlanKpi title="Conv. Rate" actual={kpiData.cr.a!=null?kpiData.cr.a+"%":null} plan={kpiData.cr.p+"%"} t={t}/><PlanKpi title="CTR" actual={kpiData.ct.a!=null?kpiData.ct.a+"%":null} plan={kpiData.ct.p+"%"} t={t}/></div>
    <Sec title="Trend — Actual vs Plan" icon="📊" t={t} action={<select value={trendMetric} onChange={e=>setTrendMetric(e.target.value)} style={{background:t.card,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"5px 10px",fontSize:11,fontWeight:600,color:t.primary,cursor:"pointer"}}>{metrics.map(m=><option key={m.k} value={m.k}>{m.l}</option>)}</select>}><Cd t={t}><ResponsiveContainer width="100%" height={260}><ComposedChart data={trendData}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="m" tick={{fill:t.textSec,fontSize:10}}/><YAxis tick={{fill:t.textMuted,fontSize:10}} tickFormatter={v=>isCur?$s(v):isPct?v+"%":N(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar dataKey="Actual" fill={t.primary} radius={[4,4,0,0]}/><Line type="monotone" dataKey="Plan" stroke={t.orange} strokeWidth={2} strokeDasharray="5 3" dot={{r:3,fill:t.orange}}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    <Sec title="Monthly Breakdown — All Metrics (A / P / Gap)" icon="📋" t={t} action={isF&&<span style={{fontSize:9,color:t.orange,fontWeight:600}}>⚠️ Filtered by entity</span>}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{THD.map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i===0?"left":"right",color:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i===0?60:100}}>{h}</th>)}</tr></thead><tbody>{mpd.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.m}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.gpa} plan={r.gpp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.sa} plan={r.sp} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ia} plan={r.ip} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cra} plan={r.crp} t={t} isMoney={false} suffix="%"/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cta} plan={r.ctp} t={t} isMoney={false} suffix="%"/></td></tr>)}</tbody></table><div style={{padding:"8px 14px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider}}>Each cell: <strong style={{color:t.text}}>Actual</strong> / <span>Plan</span> / <span style={{color:t.green}}>Gap</span></div></div></Sec>
    <Sec title="⭐ ASIN Breakdown" icon="📋" t={t} action={<div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:10,color:t.textMuted}}>Month:</span><Sel value={tblMonth} onChange={setTblMonth} options={MS} label="All Months" t={t}/></div>}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{AHDL.map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i<=1?"left":"right",color:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i<=1?70:100}}>{h}</th>)}</tr></thead><tbody>{fPlanBk.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"10px 12px",fontFamily:"monospace",fontSize:10,borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.a}</td><td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.br}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.ga} plan={r.gp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.sa} plan={r.sp} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ia} plan={r.ip} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cra} plan={r.crp} t={t} isMoney={false} suffix="%"/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cta} plan={r.ctp} t={t} isMoney={false} suffix="%"/></td></tr>)}</tbody></table><div style={{padding:"8px 14px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider,position:"sticky",bottom:0,background:t.card}}>{fPlanBk.length} ASINs · Ads: lower = better (reversed color)</div></div></Sec>
  </div>;
}

/* ═══════════ PRODUCT ═══════════ */
function ProdPage({t,fAsin,fDaily}){
  const tR=fAsin.reduce((s,a)=>s+a.r,0),tN=fAsin.reduce((s,a)=>s+a.n,0),tU=fAsin.reduce((s,a)=>s+a.u,0);
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Revenue" value={$(tR)} icon="💰" t={t}/><KpiCard title="Net Profit" value={$(tN)} icon="📈" t={t}/><KpiCard title="Margin" value={(tR?(tN/tR*100).toFixed(2):0)+"%"} icon="🎯" t={t}/><KpiCard title="Units" value={N(tU)} icon="📦" t={t}/></div>
    <Sec title="Revenue & NP Trend" icon="📈" t={t}><TrendChart data={fDaily} t={t}/></Sec>
    <Sec title="ASIN Table" icon="📋" t={t}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{["ASIN","Brand","Seller","Revenue","Net Profit","Margin%","Units","CR%","ACoS","ROAS"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=3?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fAsin.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontFamily:"monospace",fontSize:11,borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.a}</td><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.b}</td><td style={{padding:"8px 12px",borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.sl}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(1)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.cr}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ac<30?t.green:r.ac<50?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ac}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.ro.toFixed(2)}</td></tr>)}</tbody></table><div style={{padding:"6px 12px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider,position:"sticky",bottom:0,background:t.card}}>{fAsin.length} ASINs</div></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genAlerts([...fAsin],t)}/></div>
  </div>;
}

/* ═══════════ SHOP ═══════════ */
function ShopPage({t,fShopData,fDaily}){
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Total Revenue" value={$(fShopData.reduce((s,x)=>s+x.r,0))} icon="💰" t={t}/><KpiCard title="Total NP" value={$(fShopData.reduce((s,x)=>s+x.n,0))} icon="📈" t={t}/><KpiCard title="Avg Margin" value={(fShopData.length?(fShopData.reduce((s,x)=>s+x.m,0)/fShopData.length).toFixed(2):0)+"%"} icon="🎯" t={t}/><KpiCard title="FBA Stock" value={N(fShopData.reduce((s,x)=>s+x.f,0))} icon="📦" t={t}/></div>
    <Sec title="Revenue Trend" icon="📈" t={t}><TrendChart data={fDaily} t={t} keys={[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"}]}/></Sec>
    <Sec title="Shop Table" icon="🏪" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{["Shop","Revenue","Net Profit","Margin%","FBA Stock","Orders","Health"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=1&&i<=5?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fShopData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.s}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.f)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.o)}</td><td style={{padding:"8px 12px",borderBottom:"1px solid "+t.divider,textAlign:"center"}}>{r.m>10?<span style={{background:t.greenBg,color:t.green,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Good</span>:r.m>0?<span style={{background:t.orangeBg,color:t.orange,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Fair</span>:<span style={{background:t.redBg,color:t.red,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Poor</span>}</td></tr>)}</tbody></table></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genShopAlerts(fShopData,t)}/></div>
  </div>;
}

/* ═══════════ TEAM ═══════════ */
function TeamPage({t,fSeller,fDaily}){
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Total Revenue" value={$(fSeller.reduce((s,x)=>s+x.r,0))} icon="💰" t={t}/><KpiCard title="Total NP" value={$(fSeller.reduce((s,x)=>s+x.n,0))} icon="📈" t={t}/><KpiCard title="Avg Margin" value={(fSeller.length?(fSeller.reduce((s,x)=>s+x.m,0)/fSeller.length).toFixed(2):0)+"%"} icon="🎯" t={t}/></div>
    <Sec title="Revenue Trend" icon="📈" t={t}><TrendChart data={fDaily} t={t} keys={[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"}]}/></Sec>
    <Sec title="Seller Table" icon="👥" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{["Seller","Revenue","Net Profit","Margin%","Units","ASINs"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=1?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fSeller.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.sl}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.as}</td></tr>)}</tbody></table></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genSellerAlerts(fSeller,t)}/></div>
  </div>;
}

/* ═══════════ OPS ═══════════ */
function OpsPage({t,fDaily,fShopData}){
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Revenue" value={$(fDaily.reduce((s,x)=>s+x.revenue,0))} icon="💰" t={t}/><KpiCard title="Net Profit" value={$(fDaily.reduce((s,x)=>s+x.netProfit,0))} icon="📈" t={t}/><KpiCard title="Units" value={N(fDaily.reduce((s,x)=>s+x.units,0))} icon="📦" t={t}/></div>
    <Sec title="Daily Trend" icon="📈" t={t}><TrendChart data={fDaily} t={t}/></Sec>
    <Sec title="Shop Ops" icon="🏪" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{["Shop","Revenue","NP","Orders","FBA Stock"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=1?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fShopData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.s}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.o)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.f)}</td></tr>)}</tbody></table></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genOpsAlerts(fDaily,t)}/></div>
  </div>;
}

/* ═══════════ AI INSIGHT ═══════════ */
function AiInsight({t,live,context}){
  const[open,setOpen]=useState(false);const[loading,setLoading]=useState(false);const[insight,setInsight]=useState("");const[question,setQuestion]=useState("");
  const run=async()=>{setLoading(true);setInsight("");
    try{const data=await apiPost("ai/insight",{context,question:question||undefined});setInsight(data.insight||"No insight available")}catch(e){
      const{em,fAsin}=context;const top=fAsin?.[0];const negCount=fAsin?.filter(a=>a.n<0).length||0;let txt=`📊 Executive Summary\n\nRevenue: ${$(em?.sales)} | Net Profit: ${$(em?.netProfit)} | Margin: ${(em?.margin||0).toFixed(1)}%\n\n`;if(top)txt+=`🏆 Top ASIN: ${top.a} (${top.b}) — ${$(top.r)} revenue, ${$(top.n)} NP\n\n`;if(negCount)txt+=`⚠️ ${negCount} ASINs with negative profit need attention.`;setInsight(txt);}
    setLoading(false);};
  if(!open)return<button onClick={()=>setOpen(true)} style={{position:"fixed",bottom:20,right:20,zIndex:999,background:"linear-gradient(135deg,#3B4A8A,#6B7FD7)",color:"#fff",border:"none",borderRadius:14,padding:"12px 18px",cursor:"pointer",boxShadow:"0 4px 20px rgba(59,74,138,.3)",fontSize:13,fontWeight:700}}>🤖 AI Insight</button>;
  return<div style={{position:"fixed",bottom:20,right:20,zIndex:999,width:420,maxHeight:"70vh",background:t.card,borderRadius:14,border:"1px solid "+t.cardBorder,boxShadow:"0 12px 40px "+t.shadow,display:"flex",flexDirection:"column",overflow:"hidden"}}><div style={{padding:"12px 16px",borderBottom:"1px solid "+t.divider,display:"flex",justifyContent:"space-between",background:`linear-gradient(135deg,${t.primary},#5A6BC5)`}}><span style={{fontSize:13,fontWeight:700,color:"#fff"}}>🤖 AI Insight</span><button onClick={()=>setOpen(false)} style={{background:"rgba(255,255,255,.2)",border:"none",borderRadius:6,color:"#fff",cursor:"pointer",padding:"4px 8px",fontSize:12}}>✕</button></div><div style={{padding:12,borderBottom:"1px solid "+t.divider}}><input value={question} onChange={e=>setQuestion(e.target.value)} placeholder="Ask a question or leave blank..." style={{width:"100%",padding:"8px 12px",borderRadius:8,border:"1px solid "+t.inputBorder,background:t.inputBg,color:t.text,fontSize:12,boxSizing:"border-box"}}/><button onClick={run} disabled={loading} style={{marginTop:8,width:"100%",padding:"8px",borderRadius:8,border:"none",background:loading?t.textMuted:t.primary,color:"#fff",cursor:loading?"wait":"pointer",fontSize:12,fontWeight:700}}>{loading?"⏳ Analyzing...":"Analyze"}</button></div><div style={{flex:1,overflow:"auto",padding:14}}>{insight?<div style={{fontSize:12,color:t.textSec,lineHeight:1.7,whiteSpace:"pre-wrap"}}>{insight}</div>:<div style={{fontSize:11,color:t.textMuted,textAlign:"center",padding:20}}>Click Analyze for AI insights.</div>}</div></div>;
}

/* ═══════════ SPINNER ═══════════ */
function Spinner({t,text}){return<div style={{display:"flex",alignItems:"center",justifyContent:"center",padding:40}}><div style={{textAlign:"center"}}><div style={{width:32,height:32,border:"3px solid "+t.cardBorder,borderTopColor:t.primary,borderRadius:"50%",animation:"spin 1s linear infinite",margin:"0 auto 12px"}}/><style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style><div style={{fontSize:12,color:t.textMuted,fontWeight:600}}>{text||"Loading..."}</div></div></div>}

/* ═══════════ MAIN APP ═══════════ */
const NAV=[{id:"exec",l:"Executive Overview",i:"🏠"},{id:"inv",l:"Inventory",i:"📦"},{id:"plan",l:"ASIN Plan",i:"📋"},{id:"prod",l:"Product Performance",i:"📈"},{id:"shops",l:"Shop Performance",i:"🏪"},{id:"team",l:"Team Performance",i:"👥"},{id:"daily",l:"Daily / Ops",i:"⚡"}];

export default function App(){
  const{mob,tab}=useResp();
  const[pg,setPg]=useState("exec");const[sb,setSb]=useState(true);const[isDark,setDark]=useState(false);
  const t=isDark?TH.dark:TH.light;const cn=NAV.find(n=>n.id===pg);

  const[live,setLive]=useState(false);
  const[dbRange,setDbRange]=useState(null);const[dbConnecting,setDbConnecting]=useState(true);
  const[mobileFilters,setMobileFilters]=useState(false);
  const defaultEnd=new Date().toISOString().slice(0,10);
  const defaultStart=new Date(Date.now()-30*86400000).toISOString().slice(0,10);
  const[sd,setSd]=useState(defaultStart);const[ed,setEd]=useState(defaultEnd);
  const[activePeriod,setActivePeriod]=useState(null);
  const[store,setStore]=useState("All");const[seller,setSeller]=useState("All");
  const[brand,setBrand]=useState("All");const[asinF,setAsinF]=useState("All");
  const[planYear,setPlanYear]=useState(String(new Date().getFullYear()));
  const planYearOpts=useMemo(()=>{const c=new Date().getFullYear();return[String(c-1),String(c),String(c+1)]},[]);
  const clearDates=()=>{setSd(defaultStart);setEd(defaultEnd);setActivePeriod(null)};

  // ═══════════ LIVE DATA STATE ═══════════
  const[em,setEm]=useState(EMPTY_EM);
  const[prevEm,setPrevEm]=useState(null);
  const[fDaily,setFDaily]=useState([]);
  const[fAsin,setFAsin]=useState([]);
  const[fShopData,setFShopData]=useState([]);
  const[fSeller,setFSeller]=useState([]);
  const[invData,setInvData]=useState({});
  const[invShop,setInvShop]=useState([]);
  const[invTrend,setInvTrend]=useState([]);
  const[planKpiState,setPlanKpiState]=useState({gp:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}});
  const[monthPlanState,setMonthPlanState]=useState([]);
  const[asinPlanBkState,setAsinPlanBkState]=useState([]);
  const[masterList,setMasterList]=useState([]);
  const[loading,setLoading]=useState(false);

  const opts=useBidirectionalFilters(store,seller,brand,asinF,masterList);
  useEffect(()=>{if(store!=="All"&&opts.stores.length&&!opts.stores.includes(store))setStore("All")},[opts.stores]);
  useEffect(()=>{if(seller!=="All"&&opts.sellers.length&&!opts.sellers.includes(seller))setSeller("All")},[opts.sellers]);
  useEffect(()=>{if(brand!=="All"&&opts.brands.length&&!opts.brands.includes(brand))setBrand("All")},[opts.brands]);
  useEffect(()=>{if(asinF!=="All"&&opts.asins.length&&!opts.asins.includes(asinF))setAsinF("All")},[opts.asins]);

  // ═══════════ INIT: Connect to backend ═══════════
  useEffect(()=>{
    (async()=>{
      try{
        const ok=await checkBackend();setLive(ok);
        if(ok){
          const f=await api("filters").catch(()=>null);
          if(f){
            // Build masterList for bidirectional filtering
            const ml=[];
            const shopNames=(f.shops||[]).map(s=>s.shop||s.name).filter(Boolean);
            if(f.asins){
              f.asins.forEach(a=>{
                // If server provides shop mapping for this ASIN, use it
                const shops=a.shops&&a.shops.length?a.shops:shopNames.length?[shopNames[0]]:["Unknown"];
                shops.forEach(sh=>ml.push({a:a.asin||"",b:a.brand||a.store||"",st:sh,sl:a.seller||""}));
              });
            }
            // Also ensure all shops appear even if no ASIN maps to them yet
            shopNames.forEach(sh=>{if(!ml.some(x=>x.st===sh))ml.push({a:"",b:"",st:sh,sl:""});});
            setMasterList(ml);
            console.log("Filters loaded:",{shops:shopNames.length,sellers:(f.sellers||[]).length,brands:(f.brands||[]).length,asins:(f.asins||[]).length,masterList:ml.length});
          }
          const dr=await api("date-range").catch(()=>null);
          if(dr){setDbRange(dr);/* end date stays as today (defaultEnd), start is 30d ago from today */}
          api("inventory/snapshot").then(d=>setInvData(d||{})).catch(()=>{});
          api("inventory/by-shop").then(d=>setInvShop((d||[]).map(r=>({s:r.shop,fba:r.fbaStock||0,inb:r.inbound||0,res:r.reserved||0,crit:r.criticalSkus||0,st:r.sellThrough||0,doh:r.daysOfSupply||0})))).catch(()=>{});
          api("inventory/stock-trend").then(d=>setInvTrend((d||[]).map(r=>{const dt=new Date(r.date);return{d:MS[dt.getMonth()]+" "+dt.getDate(),v:parseInt(r.fbaStock)||0}}))).catch(()=>{});
        }
      }catch{}
      setDbConnecting(false);
    })();
  },[]);

  // ═══════════ FETCH DATA when filters/dates change ═══════════
  useEffect(()=>{
    if(!live||dbConnecting)return;
    let cancelled=false;
    const p={start:sd,end:ed,store,seller,brand,asin:asinF};
    setLoading(true);
    (async()=>{
      try{
        const summary=await api("exec/summary",p).catch(()=>EMPTY_EM);
        if(!cancelled)setEm(summary);
        // Previous period
        const days=Math.max(1,Math.round((new Date(ed)-new Date(sd))/86400000)+1);
        const pe=new Date(new Date(sd+"T00:00:00").getTime()-86400000);
        const ps=new Date(pe.getTime()-(days-1)*86400000);
        const prev=await api("exec/summary",{...p,start:ps.toISOString().slice(0,10),end:pe.toISOString().slice(0,10)}).catch(()=>null);
        if(!cancelled)setPrevEm(prev&&prev.sales?prev:null);
        // Daily
        const daily=await api("exec/daily",p).catch(()=>[]);
        if(!cancelled)setFDaily((daily||[]).map(r=>{const dt=new Date(r.date);return{date:r.date,label:MS[dt.getMonth()]+" "+dt.getDate(),revenue:parseFloat(r.revenue)||0,netProfit:parseFloat(r.netProfit)||0,units:parseInt(r.units)||0}}));
        // ASINs
        const asins=await api("product/asins",{start:sd,end:ed,store,seller,brand,asin:asinF}).catch(()=>[]);
        if(!cancelled)setFAsin((asins||[]).map(r=>({a:r.asin,b:r.brand||"",st:r.brand||"",sl:r.seller||"",r:parseFloat(r.revenue)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,u:parseInt(r.units)||0,cr:parseFloat(r.cr)||0,ac:parseFloat(r.acos)||0,ro:parseFloat(r.acos)>0?(100/parseFloat(r.acos)):0})));
        // Shops
        const shops=await api("shops",{start:sd,end:ed,store,seller}).catch(()=>[]);
        if(!cancelled)setFShopData((shops||[]).map(r=>({s:r.shop,r:parseFloat(r.revenue)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,f:parseInt(r.fbaStock)||0,o:parseInt(r.orders)||0})));
        // Team
        const team=await api("team",{start:sd,end:ed,seller,store}).catch(()=>[]);
        if(!cancelled)setFSeller((team||[]).map(r=>({sl:r.seller,r:parseFloat(r.revenue)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,u:parseInt(r.units)||0,as:parseInt(r.asinCount)||0})));
      }catch(e){console.error("Fetch error:",e)}
      if(!cancelled)setLoading(false);
    })();
    return()=>{cancelled=true};
  },[live,dbConnecting,sd,ed,store,seller,brand,asinF]);

  // ═══════════ FETCH PLAN DATA ═══════════
  useEffect(()=>{
    if(!live||dbConnecting)return;
    let cancelled=false;
    (async()=>{
      try{
        const[planRes,actualsRes]=await Promise.all([
          api("plan/data",{year:planYear,brand,seller,asin:asinF}).catch(()=>null),
          api("plan/actuals",{year:planYear,brand,seller,asin:asinF}).catch(()=>null)
        ]);
        if(cancelled)return;
        const plan=planRes||{};const actuals=actualsRes||{};
        const monthlyPlan=plan.monthlyPlan||{};const asinPlan=plan.asinPlan||{};
        const monthlyActuals=actuals.monthly||[];const asinBk=actuals.asinBreakdown||[];

        // Build planKpi: merge plan totals with actual totals
        const pk=plan.kpi||{gp:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}};
        // Fill actuals into kpi
        const aT={rv:0,gp:0,ad:0,un:0,se:0,im:0,cr:[],ct:[]};
        monthlyActuals.forEach(m=>{aT.rv+=m.ra||0;aT.gp+=m.gpa||0;aT.ad+=m.aa||0;aT.un+=m.ua||0;aT.se+=m.sa||0;if(m.cra)aT.cr.push(m.cra);});
        pk.rv.a=aT.rv;pk.gp.a=aT.gp;pk.ad.a=aT.ad;pk.un.a=aT.un;pk.se.a=aT.se;
        pk.cr.a=aT.cr.length?aT.cr.reduce((s,v)=>s+v,0)/aT.cr.length:0;
        setPlanKpiState(pk);

        // Build monthPlanData: merge plan + actuals per month
        const mpd=MS.map((mName,i)=>{
          const mn=i+1;const pp=monthlyPlan[mn]||{};const aa=monthlyActuals.find(m=>m.mn===mn)||{};
          return{m:mName,gpa:aa.gpa||0,gpp:pp.gp||0,ra:aa.ra||0,rp:pp.rv||0,aa:aa.aa||0,ap:pp.ad||0,ua:aa.ua||0,up:pp.un||0,sa:aa.sa||0,sp:pp.se||0,ia:aa.ia||0,ip:pp.im||0,cra:aa.cra||0,crp:pp.cr||0,cta:aa.cta||0,ctp:pp.ct||0};
        });
        setMonthPlanState(mpd);

        // Build asinBreakdown: merge plan + actuals per ASIN
        const allAsins=new Set([...Object.keys(asinPlan),...asinBk.map(a=>a.a)]);
        const abk=[...allAsins].map(asin=>{
          const pd=asinPlan[asin]||{brand:"",months:{}};const ad=asinBk.find(a=>a.a===asin)||{};
          // Sum plan across months
          let pTot={rv:0,gp:0,ad:0,un:0,se:0,im:0,cr:[],ct:[]};
          Object.values(pd.months||{}).forEach(m=>{pTot.rv+=m.rv||0;pTot.gp+=m.gp||0;pTot.ad+=m.ad||0;pTot.un+=m.un||0;pTot.se+=m.se||0;if(m.cr)pTot.cr.push(m.cr);});
          const crP=pTot.cr.length?pTot.cr.reduce((s,v)=>s+v,0)/pTot.cr.length:0;
          return{a:asin,br:pd.brand||ad.br||"",sl:ad.sl||"",ga:ad.ga||0,gp:pTot.gp,ra:ad.ra||0,rp:pTot.rv,aa:ad.aa||0,ap:pTot.ad,ua:ad.ua||0,up:pTot.un,sa:ad.sa||0,sp:pTot.se,ia:ad.ia||0,ip:pTot.im,cra:ad.cra||0,crp:crP,cta:ad.cta||0,ctp:0};
        }).sort((a,b)=>(b.ga||0)-(a.ga||0));
        setAsinPlanBkState(abk);
      }catch(e){console.error("Plan fetch error:",e)}
    })();
    return()=>{cancelled=true};
  },[live,dbConnecting,planYear,brand,seller,asinF]);

  const fShopRev=useMemo(()=>fShopData.map(s=>({s:s.s,r:s.r,n:s.n})),[fShopData]);

  const pctChg=useCallback((cur,prev)=>{if(prev==null||prev===0)return undefined;return((cur-prev)/Math.abs(prev))*100},[]);

  // Filter visibility per page
  const showStore=["exec","prod","shops","team","daily"].includes(pg);
  const showSeller=["exec","prod","shops","team","plan"].includes(pg);
  const showBrand=["exec","plan","prod"].includes(pg);
  const showAsin=["exec","plan","prod"].includes(pg);

  if(dbConnecting)return<div style={{display:"flex",alignItems:"center",justifyContent:"center",height:"100vh",background:t.bg}}><Spinner t={t} text="Connecting..."/></div>;

  return<div style={{display:"flex",flexDirection:mob?"column":"row",height:"100vh",background:t.bg,fontFamily:"'DM Sans',system-ui,-apple-system,sans-serif",color:t.text,overflow:"hidden",transition:"background .3s"}}>
    {/* SIDEBAR (desktop) or BOTTOM NAV (mobile) */}
    {!mob&&<div style={{width:(tab||!sb)?56:220,background:t.sidebar,borderRight:"1px solid "+t.sidebarBorder,display:"flex",flexDirection:"column",transition:"width .2s",flexShrink:0,overflow:"hidden"}}>
      <div style={{padding:"14px 14px 10px",display:"flex",alignItems:"center",gap:8,borderBottom:"1px solid "+t.sidebarBorder,minHeight:50}}><div style={{width:32,height:32,borderRadius:8,background:"linear-gradient(135deg,#3B4A8A,#6B7FD7)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:800,color:"#fff",flexShrink:0}}>A</div>{!tab&&sb&&<div><div style={{fontSize:14,fontWeight:800,color:t.text,lineHeight:1.1}}>Amazon</div><div style={{fontSize:8,color:t.textMuted,letterSpacing:1.5,fontWeight:700,textTransform:"uppercase"}}>Dashboard</div></div>}</div>
      <div style={{flex:1,padding:6,overflowY:"auto"}}>{NAV.map(n=><button key={n.id} onClick={()=>setPg(n.id)} style={{width:"100%",display:"flex",alignItems:"center",gap:8,padding:(!tab&&sb)?"10px 12px":"10px 0",borderRadius:8,border:"none",cursor:"pointer",marginBottom:2,background:pg===n.id?t.sidebarActive:"transparent",color:pg===n.id?t.primary:t.textSec,justifyContent:(!tab&&sb)?"flex-start":"center",fontSize:12}}><span style={{fontSize:15,flexShrink:0}}>{n.i}</span>{!tab&&sb&&<span style={{fontWeight:pg===n.id?700:500,whiteSpace:"nowrap"}}>{n.l}</span>}</button>)}</div>
      {!tab&&<div style={{padding:6,borderTop:"1px solid "+t.sidebarBorder}}><button onClick={()=>setSb(!sb)} style={{width:"100%",padding:"8px 12px",borderRadius:8,border:"none",cursor:"pointer",background:"transparent",color:t.textMuted,display:"flex",alignItems:"center",justifyContent:sb?"flex-start":"center",gap:6,fontSize:11,fontWeight:600}}><span>{sb?"◀":"▶"}</span>{sb&&<span>Collapse</span>}</button></div>}
    </div>}

    <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",paddingBottom:mob?56:0}}>
      {/* TOPBAR */}
      <div style={{background:t.topbar,borderBottom:"1px solid "+t.cardBorder,padding:mob?"10px 12px":"12px 20px",display:"flex",flexDirection:"column",gap:8,flexShrink:0}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>{mob&&<button onClick={()=>setMobileFilters(!mobileFilters)} style={{background:t.primaryLight,border:"1px solid "+t.primary+"33",borderRadius:8,padding:"6px 10px",cursor:"pointer",fontSize:12,color:t.primary,fontWeight:700}}>☰</button>}<span style={{fontSize:mob?14:16,fontWeight:800,color:t.text}}>{cn?.i} {cn?.l}</span></div>
          <div style={{display:"flex",alignItems:"center",gap:6}}>
            {loading&&<span style={{fontSize:9,color:t.orange,fontWeight:600}}>⏳</span>}
            <span style={{fontSize:9,fontWeight:700,padding:"3px 10px",borderRadius:10,background:live?"#EAFAF1":"#FFF8EC",color:live?"#1B8553":"#C67D1A",letterSpacing:.5}}>{live?"🟢 Live DB":"🟡 No DB"}</span>
            <button onClick={()=>setDark(!isDark)} style={{background:t.card,border:"1px solid "+t.inputBorder,borderRadius:8,padding:"5px 10px",cursor:"pointer",fontSize:12,color:t.textSec}}>{isDark?"☀":"🌙"}</button>
          </div>
        </div>
        {/* FILTER BAR */}
        {pg!=="inv"&&(!mob||mobileFilters)&&<div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
          {pg==="exec"&&<><DateInput label="Start" value={sd} onChange={v=>{setSd(v);setActivePeriod(null)}} t={t}/><DateInput label="End" value={ed} onChange={v=>{setEd(v);setActivePeriod(null)}} t={t}/><PeriodBtns onSelect={(s,e,l)=>{setSd(s);setEd(e);setActivePeriod(l)}} active={activePeriod} t={t} refDate={defaultEnd}/><ClearBtn onClick={clearDates} t={t}/></>}
          {pg==="plan"&&<><Sel value={planYear} onChange={setPlanYear} options={planYearOpts} label="All Years" t={t}/></>}
          {["prod","shops","team","daily"].includes(pg)&&<><DateInput label="Start" value={sd} onChange={v=>{setSd(v);setActivePeriod(null)}} t={t}/><DateInput label="End" value={ed} onChange={v=>{setEd(v);setActivePeriod(null)}} t={t}/><PeriodBtns onSelect={(s,e,l)=>{setSd(s);setEd(e);setActivePeriod(l)}} active={activePeriod} t={t} refDate={defaultEnd}/><ClearBtn onClick={clearDates} t={t}/></>}
          {showStore&&<Sel value={store} onChange={setStore} options={opts.stores} label="All Shops" t={t}/>}
          {showSeller&&<Sel value={seller} onChange={setSeller} options={opts.sellers} label="All Sellers" t={t}/>}
          {showBrand&&<Sel value={brand} onChange={setBrand} options={opts.brands} label="All Brands" t={t}/>}
          {showAsin&&<Sel value={asinF} onChange={setAsinF} options={opts.asins} label="All ASINs" t={t}/>}
        </div>}
      </div>

      {/* CONTENT */}
      <div style={{flex:1,overflow:"auto",padding:mob?12:20}}>
        {pg==="exec"&&<ExecPage t={t} fAsin={fAsin} fShop={fShopRev} fDaily={fDaily} em={em} sd={sd} ed={ed} prevEm={prevEm} pctChg={pctChg} mob={mob}/>}
        {pg==="inv"&&<InvPage t={t} mob={mob} invData={invData} invShop={invShop} invTrend={invTrend}/>}
        {pg==="plan"&&<PlanPage t={t} planKpi={planKpiState} monthPlanData={monthPlanState} asinPlanBkData={asinPlanBkState} seller={seller} brand={brand} asinF={asinF}/>}
        {pg==="prod"&&<ProdPage t={t} fAsin={fAsin} fDaily={fDaily}/>}
        {pg==="shops"&&<ShopPage t={t} fShopData={fShopData} fDaily={fDaily}/>}
        {pg==="team"&&<TeamPage t={t} fSeller={fSeller} fDaily={fDaily}/>}
        {pg==="daily"&&<OpsPage t={t} fDaily={fDaily} fShopData={fShopData}/>}
        <div style={{height:30}}/>
      </div>
    </div>

    {/* MOBILE BOTTOM NAV */}
    {mob&&<div style={{position:"fixed",bottom:0,left:0,right:0,background:t.sidebar,borderTop:"1px solid "+t.sidebarBorder,display:"flex",justifyContent:"space-around",padding:"6px 0",zIndex:998}}>{NAV.map(n=><button key={n.id} onClick={()=>{setPg(n.id);setMobileFilters(false)}} style={{display:"flex",flexDirection:"column",alignItems:"center",gap:2,background:"none",border:"none",cursor:"pointer",padding:"4px 6px",borderRadius:6,color:pg===n.id?t.primary:t.textMuted,fontSize:9,fontWeight:pg===n.id?700:500,minWidth:0}}><span style={{fontSize:16}}>{n.i}</span><span style={{whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis",maxWidth:48}}>{n.l.split(" ")[0]}</span></button>)}</div>}

    <AiInsight t={t} live={live} context={{em,fAsin:fAsin.slice(0,10)}}/>
  </div>;
}
