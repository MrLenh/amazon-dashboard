import React, { useState, useRef, useEffect, useMemo, useCallback } from "react";
import ReactDOM from "react-dom";
import { checkBackend, api, apiPost } from "./api.js";
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, AreaChart, Area, ComposedChart, Cell, ScatterChart, Scatter,
  ZAxis, PieChart, Pie, ReferenceLine
} from "recharts";

/* ═══════════ THEMES ═══════════ */
const TH={
  light:{bg:"#F0F2F8",card:"#FFFFFF",cardBorder:"#E2E6EF",sidebar:"#FFFFFF",sidebarBorder:"#E8ECF3",sidebarActive:"#EEF0F8",topbar:"#FFFFFF",text:"#1A1D26",textSec:"#4A5068",textMuted:"#8890A8",primary:"#3B4A8A",primaryLight:"#EEF0F8",primaryGhost:"#F5F6FB",green:"#1B8553",greenBg:"#EAFAF1",red:"#D4380D",redBg:"#FFF1EC",orange:"#C67D1A",orangeBg:"#FFF8EC",blue:"#3B82F6",purple:"#8B5CF6",chartGrid:"#E8ECF3",inputBg:"#F5F6FA",inputBorder:"#D0D5E0",tableBg:"#F8F9FC",tableHover:"#EEF0F8",divider:"#E8ECF3",kpiIcon:"#EEF0F8",shadow:"rgba(59,74,138,0.10)"},
  dark:{bg:"#0C0E16",card:"#161825",cardBorder:"#2A2E42",sidebar:"#111320",sidebarBorder:"#252840",sidebarActive:"#1E2348",topbar:"#111320",text:"#F1F3F9",textSec:"#B0B5CC",textMuted:"#727A96",primary:"#8B9EF0",primaryLight:"#1C2040",primaryGhost:"#191C32",green:"#4AE09A",greenBg:"#0F2E20",red:"#FF7A6A",redBg:"#2E1616",orange:"#FFC05C",orangeBg:"#2E2412",blue:"#6CB4FF",purple:"#B494FF",chartGrid:"#2A2E42",inputBg:"#1A1D2E",inputBorder:"#353952",tableBg:"#1A1D2E",tableHover:"#1E2348",divider:"#252840",kpiIcon:"#1E2348",shadow:"rgba(0,0,0,0.5)"},
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
const TIPS={sales:"Total revenue from all sales",units:"Total units sold",refunds:"Refunded orders",advCost:"Total ad spend (PPC)",shippingCost:"FBA shipping fees",refundCost:"Cost of processing refunds",amazonFees:"Referral + FBA fees",cogs:"Cost of Goods Sold",netProfit:"Revenue − All Costs",estPayout:"Estimated Amazon payout",realAcos:"Ad Spend / Sales × 100%",pctRefunds:"Refunds / Orders × 100%",margin:"Net Profit / Revenue × 100%",sessions:"Product page views",gp:"SUM(grossProfit) from seller_board_sales",cr:"Orders / Sessions × 100%",ctr:"Clicks / Impressions × 100%",sellThrough:"Units Sold / (Sold + Ending Inventory)",doh:"Current Stock / Avg Daily Sales",fbaStock:"Total FBA inventory (from Seller Board Stock). Includes Available + Reserved units across all warehouses",invAvail:"Units ready to ship. Source: fba_inventory_planning → available",invReserved:"Units held by Amazon (pending orders, transfers). Source: fba_inventory_planning → totalReservedQuantity",invCritical:"SKUs with ≤ 7 days of supply remaining — need restocking urgently",invInbound:"Units currently in transit to Amazon fulfillment centers",invDaysSupply:"Average days current stock will last based on recent sales velocity. Low = restock soon, High = excess inventory",storageFee:"Estimated monthly FBA storage fee from Amazon. Includes standard + aged inventory surcharge (>90 days). Source: fba_inventory_planning → estimatedStorageCostNextMonth",revenue:"Total sales revenue across all channels in selected period",np:"Revenue minus all costs (ads, COGS, Amazon fees, shipping, refunds)",avgMargin:"Average Net Profit ÷ Revenue across all entities shown",aov:"Average revenue per order = Total Sales ÷ Total Orders",upo:"Average units per order = Total Units ÷ Total Orders",prodRev:"Revenue from seller_board_product for selected ASINs/shops",prodNP:"Net Profit per ASIN from seller_board_product",prodMargin:"Net Profit ÷ Revenue per product",prodUnits:"Total units sold per ASIN in selected period",shopFba:"Latest FBA stock count from seller_board_stock per shop",teamRev:"Total revenue across all sellers in selected period",teamNP:"Total net profit across all sellers",teamMargin:"Average margin across all sellers",opsRev:"Daily revenue from seller_board_product (last 60 days)",opsNP:"Daily net profit from seller_board_product",opsUnits:"Daily units from seller_board_product",stockValue:"Estimated inventory value = unit cost (from current snapshot) × FBA Stock (from daily). Filters by month. Will use exact data when IT adds stockValue column to daily table."};

/* ═══════════ BIDIRECTIONAL FILTER HOOK ═══════════ */
function useBidirectionalFilters(store,seller,asinF,masterList){
  return useMemo(()=>{
    const ex=excl=>{let d=masterList;if(excl!=='store'&&store!=='All')d=d.filter(x=>x.st===store);if(excl!=='seller'&&seller!=='All')d=d.filter(x=>x.sl===seller);if(excl!=='asin'&&asinF!=='All')d=d.filter(x=>x.a===asinF);return d};
    return{stores:[...new Set(ex('store').map(x=>x.st))].filter(Boolean).sort(),sellers:[...new Set(ex('seller').map(x=>x.sl))].filter(Boolean).sort(),asins:[...new Set(ex('asin').map(x=>x.a))].filter(Boolean).sort()};
  },[store,seller,asinF,masterList]);
}

/* ═══════════ RESPONSIVE HOOK ═══════════ */
function useResp(){const[w,setW]=useState(window.innerWidth);useEffect(()=>{const h=()=>setW(window.innerWidth);window.addEventListener('resize',h);return()=>window.removeEventListener('resize',h)},[]);return{mob:w<768,tab:w>=768&&w<1024};}

/* ═══════════ SHARED COMPONENTS ═══════════ */
function Tip({text,t}){const ref=React.useRef(null);const[s,setS]=useState(false);const[pos,setPos]=useState({top:0,left:0});const show=()=>{if(ref.current){const r=ref.current.getBoundingClientRect();setPos({top:r.bottom+6,left:Math.max(10,Math.min(r.left+r.width/2-80,window.innerWidth-280))});}setS(true);};return<span ref={ref} style={{position:"relative",display:"inline-flex",cursor:"help"}} onMouseEnter={show} onMouseLeave={()=>setS(false)}><span style={{fontSize:10,color:t.textMuted,marginLeft:3}}>ⓘ</span>{s&&ReactDOM.createPortal(<div style={{position:"fixed",top:pos.top,left:pos.left,background:"#1e293b",color:"#f1f5f9",padding:"7px 12px",borderRadius:8,fontSize:11.5,whiteSpace:"normal",textTransform:"none",letterSpacing:"normal",fontFamily:"'Segoe UI',system-ui,-apple-system,sans-serif",zIndex:99999,boxShadow:"0 4px 16px rgba(0,0,0,.25)",fontWeight:400,maxWidth:280,width:"max-content",lineHeight:1.5,pointerEvents:"none"}}>{text}</div>,document.body)}</span>}
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
const Sel=({value,onChange,options,label,t,renderLabel})=><select value={value} onChange={e=>onChange(e.target.value)} style={{background:t.card,color:value==="All"?t.textMuted:t.text,border:"1px solid "+(value==="All"?t.inputBorder:t.primary+"66"),borderRadius:10,padding:"7px 14px",fontSize:12,fontWeight:value==="All"?500:600,cursor:"pointer",transition:"all .15s"}}><option value="All">{label}</option>{options.map(o=><option key={o} value={o}>{renderLabel?renderLabel(o):o}</option>)}</select>;
function AsinSel({value,onChange,options,label,t}){
  const[open,setOpen]=useState(false);const[q,setQ]=useState("");const ref=useRef(null);const[hov,setHov]=useState(null);
  useEffect(()=>{const h=e=>{if(ref.current&&!ref.current.contains(e.target))setOpen(false)};document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h)},[]);
  const filtered=q?options.filter(o=>o.toLowerCase().includes(q.toLowerCase())):options;
  return<div ref={ref} style={{position:"relative",display:"inline-block"}}><button onClick={()=>{setOpen(!open);setQ("")}} style={{background:t.card,color:value==="All"?t.textMuted:t.primary,border:"1px solid "+(value==="All"?t.inputBorder:t.primary),borderRadius:10,padding:"7px 14px",fontSize:13,fontWeight:value==="All"?500:700,cursor:"pointer",minWidth:120,textAlign:"left",transition:"all .15s"}}>{value==="All"?label:value} <span style={{fontSize:9,opacity:.5}}>▾</span></button>
    {open&&<div style={{position:"absolute",top:"calc(100% + 6px)",left:0,zIndex:999,background:t.card,border:"1px solid "+t.cardBorder,borderRadius:14,boxShadow:"0 12px 40px "+t.shadow,width:280,maxHeight:420,display:"flex",flexDirection:"column",overflow:"hidden"}}>
      <div style={{padding:"12px 12px 10px",borderBottom:"1px solid "+t.divider}}><input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search ASIN..." autoFocus style={{width:"100%",padding:"10px 14px",border:"2px solid "+t.inputBorder,borderRadius:10,fontSize:14,background:t.inputBg,color:t.text,outline:"none",boxSizing:"border-box",transition:"border .15s"}} onFocus={e=>e.target.style.borderColor=t.primary} onBlur={e=>e.target.style.borderColor=t.inputBorder}/></div>
      <div style={{overflowY:"auto",flex:1,padding:"6px 6px"}}>
        <div onClick={()=>{onChange("All");setOpen(false)}} onMouseEnter={()=>setHov("all")} onMouseLeave={()=>setHov(null)} style={{padding:"10px 14px",fontSize:14,cursor:"pointer",fontWeight:value==="All"?700:500,color:value==="All"?t.primary:t.text,background:value==="All"?t.primaryLight:hov==="all"?t.tableHover:"transparent",transition:"background .12s",borderRadius:8}}>{label}</div>
        {filtered.length>0&&<div style={{padding:"8px 14px 4px",fontSize:10,color:t.textMuted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase"}}>{filtered.length} ASINs</div>}
        {filtered.map(o=><div key={o} onClick={()=>{onChange(o);setOpen(false)}} onMouseEnter={()=>setHov(o)} onMouseLeave={()=>setHov(null)} style={{padding:"10px 14px",fontSize:14,fontWeight:value===o?700:500,color:value===o?t.primary:t.text,background:value===o?t.primaryLight:hov===o?t.tableHover:"transparent",cursor:"pointer",transition:"background .12s",borderRadius:8,letterSpacing:.2}}>{o}</div>)}
        {filtered.length===0&&<div style={{padding:"20px 14px",fontSize:13,color:t.textMuted,textAlign:"center"}}>No ASINs found</div>}
      </div>
      {options.length>10&&<div style={{padding:"8px 14px",borderTop:"1px solid "+t.divider,fontSize:11,color:t.textMuted,textAlign:"center",fontWeight:600}}>{options.length} total</div>}
    </div>}
  </div>;
}

function KpiCard({title,value,change,icon,t,tip}){return<div style={{background:t.card,borderRadius:14,padding:"20px 22px",border:"1px solid "+t.cardBorder,overflow:"visible",transition:"all .2s ease"}} onMouseEnter={e=>{e.currentTarget.style.boxShadow="0 8px 28px "+t.shadow;e.currentTarget.style.transform="translateY(-1px)";}} onMouseLeave={e=>{e.currentTarget.style.boxShadow="none";e.currentTarget.style.transform="";}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}><div style={{flex:1,overflow:"visible"}}><div style={{fontSize:11.5,color:t.textSec,textTransform:"uppercase",letterSpacing:1.2,fontWeight:700,marginBottom:10}}>{title}{tip&&<Tip text={tip} t={t}/>}</div><div style={{fontSize:26,fontWeight:800,color:t.text,letterSpacing:-.5}}>{value}</div>{change!==undefined&&change!==null&&<div style={{display:"flex",alignItems:"center",gap:5,marginTop:8}}><span style={{fontSize:12,fontWeight:600,color:change>=0?t.green:t.red,background:change>=0?t.greenBg:t.redBg,padding:"3px 10px",borderRadius:10}}>{change>=0?"↑":"↓"} {Math.abs(change).toFixed(1)}%</span><span style={{fontSize:10,color:t.textMuted}}>vs prev</span></div>}</div>{icon&&<div style={{width:36,height:36,borderRadius:10,background:t.kpiIcon,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,color:t.textMuted,flexShrink:0,letterSpacing:-.5}}>{icon}</div>}</div></div>}

function PlanKpi({title,actual,plan,t,highlight,tip,fmt}){const isN=typeof actual==="number"&&typeof plan==="number";const gap=isN?actual-plan:null;const gc=gap!=null?(gap>=0?t.green:t.red):t.textMuted;const F=fmt||$;return<div style={{background:highlight?t.primaryLight:t.card,borderRadius:14,padding:"20px 22px",border:highlight?"2px solid "+t.primary:"1px solid "+t.cardBorder,overflow:"visible",transition:"all .2s ease"}} onMouseEnter={e=>{e.currentTarget.style.boxShadow="0 8px 28px "+t.shadow;}} onMouseLeave={e=>{e.currentTarget.style.boxShadow="none";}}><div style={{fontSize:11.5,color:highlight?t.primary:t.textSec,textTransform:"uppercase",letterSpacing:1.2,fontWeight:700,marginBottom:14}}>{highlight?"⭐ ":""}{title}{tip&&<Tip text={tip} t={t}/>}</div><div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:5}}><span style={{fontSize:12,color:t.textSec,fontWeight:600}}>Actual</span><span style={{fontSize:highlight?28:24,fontWeight:800,color:highlight?t.primary:t.text,letterSpacing:-.3}}>{isN?F(actual):actual}</span></div><div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline"}}><span style={{fontSize:12,color:t.textSec,fontWeight:600}}>Plan</span><span style={{fontSize:15,fontWeight:600,color:t.textSec}}>{isN?F(plan):plan}</span></div><div style={{marginTop:14,padding:"10px 14px",borderRadius:10,background:t.primaryGhost,display:"flex",justifyContent:"space-between"}}><span style={{fontSize:12,color:t.textSec,fontWeight:600}}>Gap</span><span style={{fontSize:15,fontWeight:700,color:gc}}>{gap!=null?F(gap):"—"}</span></div></div>}

const Sec=({title,icon,t,action,children})=><div style={{marginTop:28}}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:14}}><div style={{display:"flex",alignItems:"center",gap:8}}>{icon&&<span style={{fontSize:17}}>{icon}</span>}<span style={{fontSize:16,fontWeight:700,color:t.text,letterSpacing:-.2}}>{title}</span></div>{action}</div>{children}</div>;
const Cd=({children,t,style:s})=><div style={{background:t.card,borderRadius:14,padding:20,border:"1px solid "+t.cardBorder,...s}}>{children}</div>;
const CT=({active,payload,label,t:th})=>{if(!active||!payload?.length)return null;const t=th||TH.light;return<div style={{background:t.card,border:"1px solid "+t.cardBorder,borderRadius:10,padding:"10px 14px",boxShadow:"0 4px 20px "+t.shadow}}><div style={{fontSize:11,color:t.textSec,marginBottom:5,fontWeight:700}}>{label}</div>{payload.filter(p=>p.value!=null).map((p,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:6,fontSize:13,marginTop:3}}><div style={{width:8,height:8,borderRadius:4,background:p.color,flexShrink:0}}/><span style={{color:t.textSec}}>{p.name}:</span><span style={{fontWeight:700,color:p.color}}>{typeof p.value==="number"?(Math.abs(p.value)>=1?p.value.toLocaleString("en-US",{maximumFractionDigits:2}):p.value.toFixed(4)):p.value}</span></div>)}</div>};

function APG({actual,plan,t,isMoney=true,suffix="",reverse=false}){if(actual==null)return<div><div style={{fontSize:14,fontWeight:700,color:t.textMuted}}>—</div><div style={{fontSize:11,color:t.textMuted}}>Plan: {isMoney?$(plan):N(plan)+suffix}</div></div>;const gap=typeof actual==="number"?actual-plan:null;const gc=gap!=null?(reverse?(gap<=0?t.green:t.red):(gap>=0?t.green:t.red)):t.textMuted;const fA=isMoney?$(actual):(typeof actual==="number"?actual.toLocaleString():actual)+suffix;const fP=isMoney?$(plan):(typeof plan==="number"?plan.toLocaleString():plan)+suffix;const fG=gap!=null?(isMoney?$(gap):(gap>=0?"+":"")+gap.toLocaleString()+suffix):"—";return<div style={{lineHeight:1.6}}><div style={{fontSize:14,fontWeight:700,color:t.text}}>{fA}</div><div style={{fontSize:11.5,color:t.textSec}}>Plan: {fP}</div><div style={{fontSize:11.5,fontWeight:700,color:gc}}>{fG}</div></div>}
function StockVal({sv,gp,t}){const ratio=gp&&gp!==0?(sv||0)/Math.abs(gp):null;let c=t.green,bg=t.greenBg,lb="Healthy";if(ratio===null){c=t.textMuted;bg=t.cardBorder;lb="N/A";}else if(ratio>3){c=t.red;bg=t.redBg;lb="High";}else if(ratio>1.5){c=t.orange;bg=t.orangeBg;lb="Watch";}return<div style={{lineHeight:1.5}}><div style={{fontSize:13,fontWeight:700,color:t.text}}>{$(sv||0)}</div><div style={{display:"inline-flex",alignItems:"center",gap:4,marginTop:2}}><span style={{fontSize:9,fontWeight:600,color:c,background:bg,padding:"1px 6px",borderRadius:8}}>{lb}</span>{ratio!==null&&<span style={{fontSize:9,color:t.textMuted}}>{ratio.toFixed(1)}x GP</span>}</div></div>}

/* ═══════════ GRADIENT CHART HELPER ═══════════ */
const ChartGrads=({t})=><defs><linearGradient id="gRv" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.primary} stopOpacity={0.15}/><stop offset="100%" stopColor={t.primary} stopOpacity={0}/></linearGradient><linearGradient id="gNp" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.green} stopOpacity={0.15}/><stop offset="100%" stopColor={t.green} stopOpacity={0}/></linearGradient></defs>;

function TrendChart({data,t,h=240,keys}){
  const k=keys||[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"},{dk:"netProfit",n:"Net Profit",c:t.green,g:"url(#gNp)"}];
  return<Cd t={t}><ResponsiveContainer width="100%" height={h}><ComposedChart data={data}><ChartGrads t={t}/><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="label" tick={{fill:t.textSec,fontSize:11}} interval={Math.max(0,Math.floor(data.length/8))}/><YAxis tick={{fill:t.textSec,fontSize:11}} tickFormatter={v=>$s(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/>{k.map(ki=><Area key={ki.dk} type="monotone" dataKey={ki.dk} name={ki.n} fill={ki.g||"none"} stroke={ki.c} strokeWidth={2}/>)}</ComposedChart></ResponsiveContainer></Cd>;
}

/* ═══════════ ALERTS ═══════════ */
function Alerts({alerts,t}){return<Cd t={t}><div style={{display:"flex",alignItems:"center",gap:6,marginBottom:10}}><span style={{fontSize:12,fontWeight:700,color:t.orange}}>!</span><span style={{fontSize:12,fontWeight:700,color:t.orange}}>Alerts & Anomalies</span></div>{alerts.map((a,i)=><div key={i} style={{display:"flex",alignItems:"flex-start",gap:8,padding:"6px 0",borderTop:i?"1px solid "+t.divider:"none"}}><div style={{width:6,height:6,borderRadius:3,marginTop:5,background:a.s==="c"?t.red:a.s==="w"?t.orange:t.blue,flexShrink:0}}/><span style={{fontSize:11,color:t.textSec,lineHeight:1.5}}>{a.t}</span></div>)}</Cd>}

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
function genInvAlerts(shops,invData){const a=[];const tFba=invData?.fbaStock||shops.reduce((s,x)=>s+x.fba,0);const crit=invData?.criticalSkus||shops.reduce((s,x)=>s+x.crit,0);const lowSt=shops.filter(s=>s.st<2);const hiDoh=shops.filter(s=>s.doh>50);const fee=invData?.storageFee||0;a.push({s:"i",t:`Total FBA stock: ${N(tFba)} units across ${shops.length} shops`});if(crit>100)a.push({s:"c",t:`${crit} critical SKUs need restocking`});else if(crit>0)a.push({s:"w",t:`${crit} critical SKUs — monitor closely`});if(fee>5000)a.push({s:"w",t:`Storage fee ${$2(fee)}/month — consider liquidating aged inventory to reduce costs`});else if(fee>0)a.push({s:"i",t:`Storage fee ${$2(fee)}/month`});if(lowSt.length)a.push({s:"w",t:`${lowSt.length} shops with sell-through <2%: ${lowSt.map(s=>s.s).join(", ")}`});if(hiDoh.length)a.push({s:"i",t:`${hiDoh.length} shops with >50 days of health: ${hiDoh.map(s=>s.s).join(", ")} — consider reducing orders`});return a;}

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
      <Cd t={t} style={{padding:14}}><div style={{fontSize:11,fontWeight:700,color:t.textMuted,textTransform:"uppercase",marginBottom:10}}>Detailed Metrics</div><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><tbody>{[["Sales",$2(em.sales),TIPS.sales],["Units",N(em.units),TIPS.units],["Refunds",N(em.refunds),TIPS.refunds],["Ad Cost",$2(em.advCost),TIPS.advCost],["Shipping",$2(em.shippingCost),TIPS.shippingCost],["Refund Cost",$2(em.refundCost),TIPS.refundCost],["Amazon Fees",$2(em.amazonFees),TIPS.amazonFees],["COGS",$2(em.cogs),TIPS.cogs],["Net Profit",$2(em.netProfit),TIPS.netProfit],["Payout",$2(em.estPayout),TIPS.estPayout],["ACOS",(em.realAcos||0).toFixed(2)+"%",TIPS.realAcos],["% Refunds",(em.pctRefunds||0).toFixed(2)+"%",TIPS.pctRefunds],["Margin",(em.margin||0).toFixed(2)+"%",TIPS.margin],["Sessions",N(Math.round(em.sessions||0)),TIPS.sessions]].map(([l,v,tip],i)=><tr key={i} style={{borderBottom:"1px solid "+t.divider}}><td style={{padding:"6px 8px",color:t.textSec,fontWeight:500}}>{l}<Tip text={tip} t={t}/></td><td style={{padding:"6px 8px",textAlign:"right",fontWeight:700,color:t.text}}>{v}</td></tr>)}</tbody></table></Cd>
      <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:10}}><KpiCard title="Revenue" value={$(em.sales)} change={ch("sales")} icon="" t={t} tip={TIPS.sales}/><KpiCard title="Net Profit" value={$(em.netProfit)} change={ch("netProfit")} icon="" t={t} tip={TIPS.netProfit}/><KpiCard title="Margin" value={(em.margin||0).toFixed(2)+"%"} change={prevEm?em.margin-prevEm.margin:undefined} icon="" t={t} tip={TIPS.margin}/><KpiCard title="Orders" value={N(em.orders)} change={ch("orders")} t={t}/><KpiCard title="Sessions" value={N(Math.round(em.sessions||0))} change={ch("sessions")} t={t} tip={TIPS.sessions}/><KpiCard title="Ad Spend" value={$2(Math.abs(em.advCost||0))} change={ch("advCost")} t={t} tip={TIPS.advCost}/></div>
    </div>
    <Sec title="Daily Trend" icon="" t={t}><TrendChart data={fDaily} t={t} h={260} keys={[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"},{dk:"netProfit",n:"Net Profit",c:t.green,g:"url(#gNp)"},{dk:"units",n:"Units Sold",c:t.orange}]}/></Sec>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1.4fr .6fr",gap:14,marginTop:16}}>
      <Sec title="Revenue & NP by Shop" icon="" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={Math.max(220,fShop.length*42)}><BarChart data={fShop} layout="vertical" margin={{left:10,right:30}} barSize={10} barGap={4} barCategoryGap="20%"><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis type="number" tick={{fill:t.textSec,fontSize:11}} tickFormatter={v=>$s(v)}/><YAxis type="category" dataKey="s" tick={{fill:t.textSec,fontSize:11}} width={90}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar dataKey="r" name="Revenue" fill={t.primary} radius={[0,4,4,0]}/><Bar dataKey="n" name="Net Profit" fill={t.green} radius={[0,4,4,0]}>{fShop.map((e,i)=><Cell key={i} fill={e.n>=0?t.green:t.red}/>)}</Bar></BarChart></ResponsiveContainer></Cd></Sec>
      <Sec title="Revenue Share" icon="" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={200}><PieChart><Pie data={donut} innerRadius={55} outerRadius={80} dataKey="value" nameKey="name" cx="50%" cy="50%" paddingAngle={2} stroke="none">{donut.map((e,i)=><Cell key={i} fill={e.fill}/>)}</Pie><Tooltip formatter={(v)=>"$"+v.toLocaleString()}/></PieChart></ResponsiveContainer><div style={{marginTop:8}}>{donut.map((d,i)=><div key={i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:6,fontSize:10,color:t.textSec,padding:"3px 6px",borderBottom:i<donut.length-1?"1px solid "+t.divider:"none"}}><div style={{display:"flex",alignItems:"center",gap:4}}><div style={{width:8,height:8,borderRadius:2,background:d.fill,flexShrink:0}}/><span>{d.name}</span></div><div style={{display:"flex",gap:10}}><span style={{fontWeight:600}}>${d.value.toLocaleString()}</span><span style={{color:t.textMuted}}>{tR>0?(d.value/tR*100).toFixed(1):0}%</span></div></div>)}</div></Cd></Sec>
    </div>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"repeat(4,1fr)",gap:12,marginTop:14,marginBottom:14}}>
      <KpiCard title="Gross Profit" value={$(em.grossProfit)} change={ch("grossProfit")} t={t} tip={TIPS.gp}/>
      <KpiCard title="ACOS" value={(em.realAcos||0).toFixed(2)+"%" } change={prevEm?(em.realAcos||0)-(prevEm.realAcos||0):undefined} icon="" t={t} tip={TIPS.realAcos}/>
      <KpiCard title="Avg Order Value" value={em.orders>0?$2(em.sales/em.orders):"—"} change={prevEm&&em.orders>0&&prevEm.orders>0?pctChg(em.sales/em.orders,prevEm.sales/prevEm.orders):undefined} t={t} tip={TIPS.aov}/>
      <KpiCard title="Units per Order" value={em.orders>0?(em.units/em.orders).toFixed(1):"—"} change={prevEm&&em.orders>0&&prevEm.orders>0?pctChg(em.units/em.orders,prevEm.units/prevEm.orders):undefined} icon="" t={t} tip={TIPS.upo}/>
    </div>
    <Sec title="ASIN Performance" icon="" t={t}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{["ASIN","Shop","Revenue","Net Profit","Margin%","Units","CR%","ACoS","ROAS"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=2?"right":"left",color:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{fAsin.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontSize:12.5,fontWeight:600,color:t.text,letterSpacing:.3,borderBottom:"1px solid "+t.divider}}>{r.a}</td><td style={{padding:"8px 12px",fontWeight:700,color:t.text,borderBottom:"1px solid "+t.divider}}>{r.b}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(1)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.cr.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ac<30?t.green:r.ac<50?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ac.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ro>3?t.green:r.ro>2?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ro.toFixed(2)}</td></tr>)}</tbody></table><div style={{padding:"6px 12px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider,position:"sticky",bottom:0,zIndex:1,background:t.card}}>{fAsin.length} ASINs</div></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genAlerts([...fAsin],t,[{s:"i",t:`Showing ${fDaily.length} days (${fDaily[0]?.label||""} — ${fDaily[fDaily.length-1]?.label||""})`}])}/></div>
  </div>;
}

/* ═══════════ INVENTORY ═══════════ */
function InvPage({t,mob,invData,invShop,invTrend,invFeeMonthly}){
  const d=invData||{};
  const fee=d.storageFee||0;
  const feeHist=invFeeMonthly||[];
  return<div>
    <Cd t={t} style={{padding:"10px 16px",marginBottom:14,borderLeft:"3px solid "+t.blue}}><div style={{fontSize:11,color:t.textSec}}>Latest inventory snapshot{d.snapshotDate?` — data from ${d.snapshotDate}`:""}.  No time filter needed.</div></Cd>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(130px,1fr))",gap:12,marginBottom:16}}>
      <KpiCard title="FBA Stock" value={N(d.fbaStock||0)} icon="" t={t} tip={TIPS.fbaStock}/><KpiCard title="Available" value={N(d.availableInv||0)} t={t} tip={TIPS.invAvail}/><KpiCard title="Reserved" value={N(d.reserved||0)} t={t} tip={TIPS.invReserved}/><KpiCard title="Critical SKUs" value={N(d.criticalSkus||0)} t={t} tip={TIPS.invCritical}/><KpiCard title="Inbound" value={N(d.inbound||0)} t={t} tip={TIPS.invInbound}/><KpiCard title="Avg Days Supply" value={Math.round(d.avgDaysOfSupply||0)} icon="" t={t} tip={TIPS.invDaysSupply}/><KpiCard title="Storage Fee" value={$2(fee)} icon="" t={t} tip={TIPS.storageFee}/>
    </div>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:14}}>
      <Sec title="FBA Stock Trend" icon="" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={240}><AreaChart data={invTrend}><defs><linearGradient id="ig" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.primary} stopOpacity={.2}/><stop offset="100%" stopColor={t.primary} stopOpacity={0}/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="d" tick={{fill:t.textSec,fontSize:11}}/><YAxis tick={{fill:t.textSec,fontSize:11}} tickFormatter={N}/><Tooltip content={<CT t={t}/>}/><Area type="monotone" dataKey="v" name="FBA Stock" stroke={t.primary} fill="url(#ig)" strokeWidth={2}/></AreaChart></ResponsiveContainer></Cd></Sec>
      <Sec title="Sell-Through & Days of Health" icon="" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={240}><ComposedChart data={invShop}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="s" tick={{fill:t.textSec,fontSize:11}} interval={0} angle={-20} textAnchor="end" height={50}/><YAxis yAxisId="l" tick={{fill:t.textSec,fontSize:11}} unit="%"/><YAxis yAxisId="r" orientation="right" tick={{fill:t.textSec,fontSize:11}} unit="d"/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar yAxisId="l" dataKey="st" name="Sell-Through %" fill={t.green} radius={[4,4,0,0]} fillOpacity={.7}/><Line yAxisId="r" type="monotone" dataKey="doh" name="Days of Health" stroke={t.orange} strokeWidth={2} dot={{r:3}}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    </div>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:14,marginTop:14}}>
      <Sec title="Inventory Aging" icon="" t={t}><Cd t={t} style={{position:"relative"}}>{(()=>{const over90=(d.age91_180||0)+(d.age181_270||0)+(d.age271_365||0)+(d.age365plus||0);return over90>0&&<div style={{position:"absolute",top:8,right:12,background:over90>50000?t.redBg:t.orangeBg,color:over90>50000?t.red:t.orange,padding:"4px 10px",borderRadius:8,fontSize:10,fontWeight:600,zIndex:1}}>90d+ stock: {N(over90)} units</div>})()}<ResponsiveContainer width="100%" height={220}><BarChart data={[{name:"0-90d",v:d.age0_90||0},{name:"91-180d",v:d.age91_180||0},{name:"181-270d",v:d.age181_270||0},{name:"271-365d",v:d.age271_365||0},{name:"365d+",v:d.age365plus||0}]}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="name" tick={{fill:t.textSec,fontSize:11}}/><YAxis tick={{fill:t.textSec,fontSize:11}} tickFormatter={N}/><Tooltip content={<CT t={t}/>}/><Bar dataKey="v" name="Units" fill={t.orange} radius={[4,4,0,0]}/></BarChart></ResponsiveContainer></Cd></Sec>
      <Sec title="Storage Fee History" icon="" t={t}><Cd t={t}>{feeHist.length>0?<div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr>{["Month","Storage Fee","Change"].map((h,i)=><th key={i} style={{padding:"8px 12px",textAlign:i>=1?"right":"left",color:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{feeHist.map((r,i)=>{const prev=i>0?feeHist[i-1].fee:null;const chg=prev?((r.fee-prev)/Math.max(prev,1)*100):null;const[y,m]=r.month.split("-");const label=MS[parseInt(m)-1]+" "+y;return<tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:600,borderBottom:"1px solid "+t.divider}}>{label}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.fee>5000?t.red:t.text,borderBottom:"1px solid "+t.divider}}>{$2(r.fee)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{chg!==null?<span style={{fontSize:11,fontWeight:600,color:chg>0?t.red:chg<0?t.green:t.textMuted,background:chg>0?t.redBg:chg<0?t.greenBg:"transparent",padding:"2px 8px",borderRadius:10}}>{chg>0?"+":""}{chg.toFixed(1)}%</span>:<span style={{fontSize:10,color:t.textMuted}}>—</span>}</td></tr>})}</tbody></table></div>:<div style={{padding:20,textAlign:"center",color:t.textMuted,fontSize:11}}>No historical data available</div>}</Cd></Sec>
    </div>
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr",gap:14,marginTop:14}}>
      <Sec title="FBA Stock by Shop" icon="" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={Math.max(220,invShop.length*32)}><BarChart data={[...invShop].sort((a,b)=>b.fba-a.fba)} layout="vertical" margin={{left:10,right:30}} barSize={14} barCategoryGap="20%"><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis type="number" tick={{fill:t.textSec,fontSize:11}} tickFormatter={N}/><YAxis type="category" dataKey="s" tick={{fill:t.textSec,fontSize:11}} width={90}/><Tooltip content={<CT t={t}/>}/><Bar dataKey="fba" name="FBA Stock" fill={t.primary} radius={[0,4,4,0]}/></BarChart></ResponsiveContainer></Cd></Sec>
    </div>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genInvAlerts(invShop,invData)}/></div>
  </div>;
}

/* ═══════════ ASIN PLAN ═══════════ */
function PlanPage({t,planKpi,monthPlanData,asinPlanBkData,seller,store,asinF}){
  const isF=(seller&&seller!=="All")||(store&&store!=="All")||(asinF&&asinF!=="All");
  const[trendMetric,setTrendMetric]=useState("gp");
  const[planMonth,setPlanMonth]=useState("All");
  const metrics=[{k:"gp",l:"Gross Profit"},{k:"rv",l:"Revenue"},{k:"ad",l:"Ads Spend"},{k:"un",l:"Units"},{k:"se",l:"Sessions"},{k:"im",l:"Impressions"},{k:"cr",l:"Conv. Rate"},{k:"ct",l:"Click-Through Rate"}];
  const mK={gp:{a:"gpa",p:"gpp"},rv:{a:"ra",p:"rp"},ad:{a:"aa",p:"ap"},un:{a:"ua",p:"up"},se:{a:"sa",p:"sp"},im:{a:"ia",p:"ip"},cr:{a:"cra",p:"crp"},ct:{a:"cta",p:"ctp"}};
  
  const mpd=monthPlanData||[];
  const hasData=mpd.some(m=>(m.gpa||0)+(m.gpp||0)+(m.ra||0)+(m.rp||0)>0)||(asinPlanBkData||[]).length>0;
  const trendData=mpd.map(m=>{const ak=mK[trendMetric].a,pk2=mK[trendMetric].p;return{m:m.m,Actual:m[ak],Plan:m[pk2]}});
  const isCur=["gp","rv","ad"].includes(trendMetric);const isPct=["cr","ct"].includes(trendMetric);
  const kpiData=useMemo(()=>{
    const pk=planKpi||{gp:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}};
    if(planMonth==="All")return pk;
    const mi=MS.indexOf(planMonth);const m=mpd[mi];if(!m)return pk;
    return{gp:{a:m.gpa,p:m.gpp},rv:{a:m.ra,p:m.rp},ad:{a:m.aa,p:m.ap},un:{a:m.ua,p:m.up},se:{a:m.sa,p:m.sp},im:{a:m.ia,p:m.ip},cr:{a:(m.cra||0)/100,p:(m.crp||0)/100},ct:{a:(m.cta||0)/100,p:(m.ctp||0)/100}};
  },[planMonth,planKpi,mpd]);
  // Filter ASIN Breakdown by selected month
  const fPlanBk=useMemo(()=>{
    const raw=asinPlanBkData||[];
    if(planMonth==="All")return raw;
    const mi=MS.indexOf(planMonth)+1;
    return raw.map(r=>{
      const md=r.mData?.[mi]||r.mData?.[String(mi)]||{};
      return{...r,ga:md.ga||0,gp:md.gp||0,ra:md.ra||0,rp:md.rp||0,aa:md.aa||0,ap:md.ap||0,ua:md.ua||0,up:md.up||0,sa:md.sa||0,sp:md.sp||0,ia:md.ia||0,ip:md.ip||0,sv:md.sv||0,cra:md.cra||0,crp:md.crp||0,cta:md.cta||0,ctp:md.ctp||0};
    }).filter(r=>Math.abs(r.ga||0)+Math.abs(r.gp||0)+Math.abs(r.ra||0)+Math.abs(r.rp||0)+Math.abs(r.aa||0)+Math.abs(r.ap||0)+Math.abs(r.ua||0)+Math.abs(r.up||0)+Math.abs(r.sa||0)+Math.abs(r.sp||0)>0);
  },[planMonth,asinPlanBkData]);
  const THD=["Month","⭐ GP","REVENUE","ADS","UNITS","SESSIONS","IMP","CR","CTR"];
  const AHDL=["ASIN","Brand","⭐ GP","STOCK VALUE","REVENUE","ADS","UNITS","SESSIONS","IMP","CR","CTR"];
  return<div>
    {!hasData&&<div style={{padding:24,textAlign:"center",color:t.textMuted,fontSize:13,background:t.card,borderRadius:12,border:"1px solid "+t.cardBorder,marginBottom:16}}>No plan data found for this year/filter combination. Try selecting a different year or adjusting filters.</div>}
    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:12}}><span style={{fontSize:11,color:t.textMuted,fontWeight:600}}>KPI Month:</span><Sel value={planMonth} onChange={setPlanMonth} options={MS} label="All Months" t={t}/></div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:12,marginBottom:12}}><PlanKpi title="Gross Profit" actual={kpiData.gp.a} plan={kpiData.gp.p} t={t} highlight tip={TIPS.gp}/><PlanKpi title="Revenue" actual={kpiData.rv.a} plan={kpiData.rv.p} t={t} tip={TIPS.revenue}/><PlanKpi title="Ads Spend" actual={kpiData.ad.a} plan={kpiData.ad.p} t={t} tip={TIPS.advCost}/><PlanKpi title="Units" actual={kpiData.un.a} plan={kpiData.un.p} t={t} fmt={N} tip={TIPS.units}/></div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:12,marginBottom:16}}><PlanKpi title="Sessions" actual={kpiData.se.a} plan={kpiData.se.p} t={t} fmt={N} tip={TIPS.sessions}/><PlanKpi title="Impressions" actual={kpiData.im.a} plan={kpiData.im.p} t={t} fmt={N}/><PlanKpi title="Conv. Rate" actual={kpiData.cr.a!=null?Math.round(kpiData.cr.a*10000)/100:null} plan={Math.round(kpiData.cr.p*10000)/100} t={t} fmt={v=>Math.round(v*100)/100+"%"} tip={TIPS.cr}/><PlanKpi title="CTR" actual={kpiData.ct.a!=null?Math.round(kpiData.ct.a*10000)/100:null} plan={Math.round(kpiData.ct.p*10000)/100} t={t} fmt={v=>Math.round(v*100)/100+"%"} tip={TIPS.ctr}/></div>
    <div style={{padding:"10px 16px",marginBottom:16,borderRadius:10,border:"1px solid "+t.orange+"33",background:t.orange+"14",fontSize:12,color:t.textSec,lineHeight:1.6}}>
      <strong style={{color:t.orange}}>Stock Value</strong> in ASIN Breakdown is estimated: unit cost (from current inventory snapshot) × FBA Stock (daily, per month). Health ratio = Stock Value ÷ |GP|.
      <span style={{color:t.green,fontWeight:600}}> Healthy &lt;1.5x</span> ·
      <span style={{color:t.orange,fontWeight:600}}> Watch 1.5-3x</span> ·
      <span style={{color:t.red,fontWeight:600}}> High &gt;3x</span>
    </div>
    <Sec title="Trend — Actual vs Plan" icon="" t={t} action={<select value={trendMetric} onChange={e=>setTrendMetric(e.target.value)} style={{background:t.card,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"5px 10px",fontSize:11,fontWeight:600,color:t.primary,cursor:"pointer"}}>{metrics.map(m=><option key={m.k} value={m.k}>{m.l}</option>)}</select>}><Cd t={t}><ResponsiveContainer width="100%" height={260}><ComposedChart data={trendData}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="m" tick={{fill:t.textSec,fontSize:11}}/><YAxis tick={{fill:t.textSec,fontSize:11}} tickFormatter={v=>isCur?$s(v):isPct?v+"%":N(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar dataKey="Actual" fill={t.primary} radius={[4,4,0,0]}/><Line type="monotone" dataKey="Plan" stroke={t.orange} strokeWidth={2} strokeDasharray="5 3" dot={{r:3,fill:t.orange}}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    <Sec title="Monthly Breakdown — All Metrics (A / P / Gap)" icon="" t={t} action={isF&&<span style={{fontSize:9,color:t.orange,fontWeight:600}}>Filtered by entity</span>}><div style={{borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><div style={{overflowX:"auto",maxHeight:440,overflowY:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr>{THD.map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i===0?"left":"right",color:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i===0?60:100,position:"sticky",top:0,zIndex:2}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{mpd.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.m}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.gpa} plan={r.gpp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.sa} plan={r.sp} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ia} plan={r.ip} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cra} plan={r.crp} t={t} isMoney={false} suffix="%"/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cta} plan={r.ctp} t={t} isMoney={false} suffix="%"/></td></tr>)}</tbody></table></div><div style={{padding:"8px 14px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider}}>Each cell: <strong style={{color:t.text}}>Actual</strong> / <span>Plan</span> / <span style={{color:t.green}}>Gap</span></div></div></Sec>
    <Sec title="⭐ ASIN Breakdown" icon="" t={t} action={<div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:10,color:t.textMuted}}>Month:</span><Sel value={planMonth} onChange={setPlanMonth} options={MS} label="All Months" t={t}/></div>}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{AHDL.map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i<=1?"left":"right",color:h.includes("GP")?t.primary:h==="STOCK VALUE"?t.orange:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:h.includes("GP")?t.primaryLight:h==="STOCK VALUE"?t.orange+"14":t.tableBg,whiteSpace:"nowrap",minWidth:i<=1?70:100}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{fPlanBk.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"10px 12px",fontSize:12.5,fontWeight:500,letterSpacing:.3,borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.a}</td><td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.br}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.ga} plan={r.gp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.orange+"0a"}}><StockVal sv={r.sv} gp={r.ga} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.sa} plan={r.sp} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ia} plan={r.ip} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cra} plan={r.crp} t={t} isMoney={false} suffix="%"/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cta} plan={r.ctp} t={t} isMoney={false} suffix="%"/></td></tr>)}</tbody></table><div style={{padding:"8px 14px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider,position:"sticky",bottom:0,zIndex:1,background:t.card}}>{fPlanBk.length} ASINs · Stock Value = estimated (unit cost × FBA Stock) · Ads: lower = better</div></div></Sec>
  </div>;
}

/* ═══════════ PRODUCT ═══════════ */
function ProdPage({t,fAsin,fDaily}){
  const tR=fAsin.reduce((s,a)=>s+a.r,0),tN=fAsin.reduce((s,a)=>s+a.n,0),tU=fAsin.reduce((s,a)=>s+a.u,0);
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Revenue" value={$(tR)} icon="" t={t} tip={TIPS.prodRev}/><KpiCard title="Net Profit" value={$(tN)} icon="" t={t} tip={TIPS.prodNP}/><KpiCard title="Margin" value={(tR?(tN/tR*100).toFixed(2):0)+"%"} icon="" t={t} tip={TIPS.prodMargin}/><KpiCard title="Units" value={N(tU)} icon="" t={t} tip={TIPS.prodUnits}/></div>
    <Sec title="Revenue & NP Trend" icon="" t={t}><TrendChart data={fDaily} t={t}/></Sec>
    <Sec title="ASIN Table" icon="" t={t}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{["ASIN","Shop","Seller","Revenue","Net Profit","Margin%","Units","CR%","ACoS","ROAS"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=3?"right":"left",color:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{fAsin.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontSize:12.5,fontWeight:500,letterSpacing:.3,borderBottom:"1px solid "+t.divider,color:t.text}}>{r.a}</td><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.b}</td><td style={{padding:"8px 12px",borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.sl}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(1)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.cr.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ac<30?t.green:r.ac<50?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ac.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.ro.toFixed(2)}</td></tr>)}</tbody></table><div style={{padding:"6px 12px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider,position:"sticky",bottom:0,zIndex:1,background:t.card}}>{fAsin.length} ASINs</div></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genAlerts([...fAsin],t)}/></div>
  </div>;
}

/* ═══════════ SHOP ═══════════ */
function ShopPage({t,fShopData,fDaily}){
  const tGP=fShopData.reduce((s,x)=>s+(x.gp||0),0),tSV=fShopData.reduce((s,x)=>s+(x.sv||0),0);
  const THDSHOP=["Shop","⭐ GP","STOCK VALUE","REVENUE","ADS","UNITS","FBA STOCK","MARGIN","HEALTH"];
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Total GP" value={$(tGP)} icon="" t={t} tip={TIPS.gp}/><div style={{background:t.card,borderRadius:12,padding:"16px 18px",border:"2px solid "+t.orange+"55"}}><div style={{fontSize:10,color:t.orange,textTransform:"uppercase",letterSpacing:.8,fontWeight:700,marginBottom:8}}>Stock Value</div><div style={{fontSize:20,fontWeight:700,color:t.text}}>{$(tSV)}</div>{tGP!==0&&<div style={{fontSize:11,color:t.textMuted,marginTop:4}}>{(tSV/Math.abs(tGP)).toFixed(1)}x GP</div>}</div><KpiCard title="Total Revenue" value={$(fShopData.reduce((s,x)=>s+x.r,0))} icon="" t={t} tip={TIPS.revenue}/><KpiCard title="FBA Stock" value={N(fShopData.reduce((s,x)=>s+x.f,0))} icon="" t={t} tip={TIPS.shopFba}/></div>
    <Sec title="Revenue Trend" icon="" t={t}><TrendChart data={fDaily} t={t} keys={[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"}]}/></Sec>
    <Sec title="Shop Table (A / P / Gap)" icon="" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr>{THDSHOP.map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i===0?"left":i===8?"center":"right",color:h.includes("STOCK VALUE")?t.orange:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:h.includes("STOCK VALUE")?t.orange+"14":h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap"}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{fShopData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.s}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.gp} plan={r.gpP||0} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.orange+"14"}}><StockVal sv={r.sv} gp={r.gp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.r} plan={r.rvP||0} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ad} plan={r.adP||0} t={t} reverse/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.u} plan={r.unP||0} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,fontWeight:600}}>{N(r.f)}</td><td style={{padding:"10px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider,fontWeight:600}}>{r.m.toFixed(2)}%</td><td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider,textAlign:"center"}}>{r.m>10?<span style={{background:t.greenBg,color:t.green,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Good</span>:r.m>0?<span style={{background:t.orangeBg,color:t.orange,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Fair</span>:<span style={{background:t.redBg,color:t.red,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Poor</span>}</td></tr>)}</tbody></table><div style={{padding:"8px 14px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider}}>Each cell: <strong style={{color:t.text}}>Actual</strong> / Plan / <span style={{color:t.green}}>Gap</span> · Stock Health: <span style={{color:t.green}}>●</span> &lt;1.5x · <span style={{color:t.orange}}>●</span> 1.5-3x · <span style={{color:t.red}}>●</span> &gt;3x GP</div></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genShopAlerts(fShopData,t)}/></div>
  </div>;
}

/* ═══════════ TEAM ═══════════ */
function TeamPage({t,fSeller,fDaily,asinPlanBkData}){
  const[teamMonth,setTeamMonth]=useState("All");
  const asinData=useMemo(()=>{
    const raw=asinPlanBkData||[];
    let filtered=raw;
    if(teamMonth!=="All"){
      const mi=MS.indexOf(teamMonth)+1;
      filtered=raw.map(r=>{
        const md=r.mData?.[mi]||r.mData?.[String(mi)]||{};
        return{...r,ga:md.ga||0,gp:md.gp||0,na:md.na||0,np:md.np||0,ra:md.ra||0,rp:md.rp||0,aa:md.aa||0,ap:md.ap||0,ua:md.ua||0,up:md.up||0,sa:md.sa||0,sp:md.sp||0,ia:md.ia||0,ip:md.ip||0,sv:md.sv||0,cra:md.cra||0,crp:md.crp||0,cta:md.cta||0,ctp:md.ctp||0};
      }).filter(r=>Math.abs(r.ga||0)+Math.abs(r.gp||0)+Math.abs(r.ra||0)+Math.abs(r.rp||0)+Math.abs(r.aa||0)+Math.abs(r.ap||0)+Math.abs(r.ua||0)+Math.abs(r.up||0)+Math.abs(r.sa||0)+Math.abs(r.sp||0)>0);
    }
    // Sort by seller name first, then GP desc within each seller
    return[...filtered].sort((a,b)=>{
      const sc=(a.sl||"").localeCompare(b.sl||"");
      return sc!==0?sc:(b.ga||0)-(a.ga||0);
    });
  },[teamMonth,asinPlanBkData]);
  // Group by seller for summary — include margin from fSeller
  const sellerMargins=useMemo(()=>{const m={};(fSeller||[]).forEach(s=>{m[s.sl]={margin:s.m,fba:s.f};});return m;},[fSeller]);
  const sellerSummary=useMemo(()=>{
    const map={};
    asinData.forEach(r=>{
      const sl=r.sl||"Unknown";
      if(!map[sl])map[sl]={sl,ga:0,gp:0,ra:0,rp:0,aa:0,ap:0,ua:0,up:0,sv:0,cnt:0};
      const s=map[sl];s.ga+=r.ga||0;s.gp+=r.gp||0;s.ra+=r.ra||0;s.rp+=r.rp||0;s.aa+=r.aa||0;s.ap+=r.ap||0;s.ua+=r.ua||0;s.up+=r.up||0;s.sv+=r.sv||0;s.cnt++;
    });
    return Object.values(map).map(s=>({...s,margin:sellerMargins[s.sl]?.margin||0})).sort((a,b)=>(b.ga||0)-(a.ga||0));
  },[asinData,sellerMargins]);
  const THDSL=["Seller","⭐ GP","STOCK VALUE","REVENUE","ADS","UNITS","MARGIN","ASINs"];
  const THDASIN=["ASIN","Seller","Brand","⭐ GP","STOCK VALUE","REVENUE","ADS","UNITS"];
  // Detect seller group boundaries for visual separator
  const sellerBreaks=useMemo(()=>{const s=new Set();asinData.forEach((r,i)=>{if(i>0&&r.sl!==asinData[i-1].sl)s.add(i);});return s;},[asinData]);
  const noActuals=useMemo(()=>{const raw=asinPlanBkData||[];return raw.length>0&&raw.every(r=>!r.ga&&!r.ra&&!r.aa&&!r.ua);},[asinPlanBkData]);
  return<div>
    {noActuals&&<div style={{padding:"10px 14px",marginBottom:12,borderRadius:8,background:t.orange+"18",border:"1px solid "+t.orange+"44",fontSize:12,color:t.orange}}>⚠️ Actuals data = $0 — API may have failed or is still loading. Check browser console (F12) for errors.</div>}
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Total Revenue" value={$(fSeller.reduce((s,x)=>s+x.r,0))} icon="" t={t} tip={TIPS.teamRev}/><KpiCard title="Total GP" value={$(fSeller.reduce((s,x)=>s+x.n,0))} icon="" t={t} tip={TIPS.teamNP}/><KpiCard title="Avg Margin" value={(fSeller.length?(fSeller.reduce((s,x)=>s+x.m,0)/fSeller.length).toFixed(2):0)+"%"} icon="" t={t} tip={TIPS.teamMargin}/></div>
    <Sec title="Revenue Trend" icon="" t={t}><TrendChart data={fDaily} t={t} keys={[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"}]}/></Sec>
    <Sec title="Seller Performance (A / P / Gap)" icon="" t={t} action={<div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:10,color:t.textMuted}}>Month:</span><Sel value={teamMonth} onChange={setTeamMonth} options={MS} label="All Months" t={t}/></div>}><div style={{overflowX:"auto",borderRadius:12,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12.5}}><thead><tr>{THDSL.map((h,i)=><th key={i} style={{padding:"11px 14px",textAlign:i===0?"left":"right",color:h==="STOCK VALUE"?t.orange:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:10.5,textTransform:"uppercase",letterSpacing:.5,borderBottom:"2px solid "+t.divider,background:h==="STOCK VALUE"?t.orange+"14":h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i===0?80:100}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{sellerSummary.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"} style={{transition:"background .1s"}}><td style={{padding:"11px 14px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.sl}</td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.ga} plan={r.gp} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.orange+"0a"}}><StockVal sv={r.sv} gp={r.ga} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,fontWeight:600,color:mC(r.margin,t)}}>{r.margin.toFixed(2)}%</td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,fontWeight:600}}>{r.cnt}</td></tr>)}</tbody></table><div style={{padding:"8px 14px",fontSize:10.5,color:t.textMuted,borderTop:"1px solid "+t.divider}}>Each cell: <strong style={{color:t.text}}>Actual</strong> / Plan / <span style={{color:t.green}}>Gap</span> · Stock Value = estimated · Ads: lower = better</div></div></Sec>
    {asinData.length>0&&<Sec title="ASIN Detail by Seller (A / P / Gap)" icon="" t={t}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto",borderRadius:12,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12.5}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{THDASIN.map((h,i)=><th key={i} style={{padding:"11px 14px",textAlign:i<=2?"left":"right",color:h==="STOCK VALUE"?t.orange:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:10.5,textTransform:"uppercase",letterSpacing:.5,borderBottom:"2px solid "+t.divider,background:h==="STOCK VALUE"?t.orange+"14":h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i<=2?70:100}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{asinData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"} style={sellerBreaks.has(i)?{borderTop:"2px solid "+t.divider}:{transition:"background .1s"}}><td style={{padding:"11px 14px",fontSize:12.5,fontWeight:500,letterSpacing:.3,borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.a}</td><td style={{padding:"11px 14px",fontWeight:600,borderBottom:"1px solid "+t.divider,fontSize:11.5,color:t.primary}}>{r.sl||"—"}</td><td style={{padding:"11px 14px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.br}</td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.ga} plan={r.gp} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.orange+"0a"}}><StockVal sv={r.sv} gp={r.ga} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td></tr>)}</tbody></table><div style={{padding:"8px 14px",fontSize:10.5,color:t.textMuted,borderTop:"1px solid "+t.divider,position:"sticky",bottom:0,zIndex:1,background:t.card}}>{asinData.length} ASINs · Grouped by seller · Stock Value = estimated</div></div></Sec>}
    <div style={{marginTop:14}}><Alerts t={t} alerts={genSellerAlerts(fSeller,t)}/></div>
  </div>;
}

/* ═══════════ OPS ═══════════ */
function OpsPage({t,fDaily,fShopData}){
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Revenue" value={$(fDaily.reduce((s,x)=>s+x.revenue,0))} icon="" t={t} tip={TIPS.opsRev}/><KpiCard title="Gross Profit" value={$(fDaily.reduce((s,x)=>s+x.netProfit,0))} icon="" t={t} tip={TIPS.gp}/><KpiCard title="Units" value={N(fDaily.reduce((s,x)=>s+x.units,0))} icon="" t={t} tip={TIPS.opsUnits}/></div>
    <Sec title="Daily Trend" icon="" t={t}><TrendChart data={fDaily} t={t}/></Sec>
    <Sec title="Shop Ops" icon="" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr>{["Shop","Revenue","GP","Ads","Units","FBA Stock","Stock Value"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=1?"right":"left",color:h==="Stock Value"?t.orange:t.textMuted,fontWeight:700,fontSize:10,borderBottom:"2px solid "+t.divider,background:h==="Stock Value"?t.orange+"14":t.tableBg}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{fShopData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.s}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:(r.gp||0)>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.gp||0)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.ad||0)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u||0)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.f)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><StockVal sv={r.sv} gp={r.gp} t={t}/></td></tr>)}</tbody></table></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genOpsAlerts(fDaily,t)}/></div>
  </div>;
}

/* ═══════════ AI CHAT ═══════════ */
const AI_FONT="'Plus Jakarta Sans',system-ui,-apple-system,sans-serif";
// Load Plus Jakarta Sans font globally
if(typeof document!=='undefined'&&!document.getElementById('pjs-font')){const l=document.createElement('link');l.id='pjs-font';l.rel='stylesheet';l.href='https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap';document.head.appendChild(l);const s=document.createElement('style');s.textContent=`*{font-family:'Plus Jakarta Sans',system-ui,-apple-system,sans-serif!important}code,pre,.monospace,[style*="monospace"]{font-family:'JetBrains Mono','SF Mono','Cascadia Code',monospace!important}body{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}`;document.head.appendChild(s);}
const AI_HINTS={
  exec:["So sánh Jan vs Feb","Shop nào cần cắt quảng cáo?","Rủi ro lớn nhất hiện tại?"],
  inv:["Giải thích Sell-Through & Days of Health","Nên xử lý hàng tồn >90 ngày như thế nào?","Phí storage có đáng lo không?"],
  plan:["Mình có đang đúng target không?","ASIN nào lệch plan nhiều nhất?","Q2 cần điều chỉnh gì?"],
  prod:["ASIN nào nên tắt ads?","Top ASINs có gì chung?","ACOS bao nhiêu là healthy?"],
  shops:["Shop nào cần action gấp?","Revenue tập trung quá nhiều vào 1 shop?","Cải thiện shop lỗ bằng cách nào?"],
  team:["Seller nào cần coaching?","So sánh hiệu suất top vs bottom","Nên phân lại ASIN thế nào?"],
  daily:["Có anomaly gì hôm nay không?","Pattern ngày trong tuần","Trend 7 ngày gần nhất"],
};
const PG_LABEL={exec:"Executive Overview",inv:"Inventory",plan:"ASIN Plan",prod:"Product Performance",shops:"Shop Performance",team:"Team Performance",daily:"Daily Ops"};

function buildCtx(pg,d){
  const{em,fAsin,fShopData,fSeller,invData,invShop,fDaily,sd,ed}=d;
  const base={page:PG_LABEL[pg]||pg,period:`${sd} to ${ed}`};
  if(pg==="exec")return{...base,kpi:{revenue:em?.sales,np:em?.netProfit,margin:em?.margin,units:em?.units,orders:em?.orders,refundRate:em?.pctRefunds,acos:em?.realAcos,adsCost:em?.advCost,amazonFees:em?.amazonFees,cogs:em?.cogs},topAsins:fAsin?.slice(0,15)?.map(a=>({asin:a.a,shop:a.b,rev:a.r,np:a.n,margin:a.m,acos:a.ac})),shops:fShopData?.slice(0,11)?.map(s=>({shop:s.s,rev:s.r,gp:s.gp,margin:s.m,stockValue:s.sv}))};
  if(pg==="inv")return{...base,inv:{fbaStock:invData?.fbaStock,available:invData?.availableInv,reserved:invData?.reserved,criticalSkus:invData?.criticalSkus,daysSupply:invData?.avgDaysOfSupply,storageFee:invData?.storageFee,sellThrough:invData?.avgSellThrough,aging:{d0_90:invData?.age0_90,d91_180:invData?.age91_180,d181_270:invData?.age181_270,d271_365:invData?.age271_365,d365p:invData?.age365plus}},byShop:invShop?.slice(0,10)};
  if(pg==="prod")return{...base,top:fAsin?.slice(0,20)?.map(a=>({asin:a.a,shop:a.b,rev:a.r,np:a.n,margin:a.m,acos:a.ac,units:a.u})),losing:fAsin?.filter(a=>a.n<0)?.slice(0,10)?.map(a=>({asin:a.a,shop:a.b,rev:a.r,np:a.n,acos:a.ac}))};
  if(pg==="shops")return{...base,shops:fShopData?.map(s=>({shop:s.s,rev:s.r,gp:s.gp,ads:s.ad,margin:s.m,units:s.u,fba:s.f,stockValue:s.sv}))};
  if(pg==="team")return{...base,sellers:fSeller?.map(s=>({seller:s.sl,rev:s.r,np:s.n,margin:s.m,asins:s.as})),asinPlan:asinPlanBkState?.slice(0,20)?.map(a=>({asin:a.a,seller:a.sl,brand:a.br,gpActual:a.ga,gpPlan:a.gp,stockValue:a.sv,revActual:a.ra,revPlan:a.rp}))};
  if(pg==="daily")return{...base,trend:fDaily?.slice(-30)?.map(d=>({date:d.date,rev:d.revenue,np:d.netProfit,units:d.units}))};
  return base;
}

function AiChat({t,pg,contextData}){
  const[open,setOpen]=useState(false);
  const[msgs,setMsgs]=useState([]);
  const[input,setInput]=useState("");
  const[loading,setLoading]=useState(false);
  const endRef=useRef(null);
  const inputRef=useRef(null);
  const prevPg=useRef(pg);
  const mob=window.innerWidth<768;

  // Reset chat when page changes
  useEffect(()=>{if(prevPg.current!==pg){setMsgs([]);prevPg.current=pg;}},[pg]);
  // Auto scroll
  useEffect(()=>{endRef.current?.scrollIntoView({behavior:"smooth"})},[msgs,loading]);
  // Focus input on open
  useEffect(()=>{if(open)setTimeout(()=>inputRef.current?.focus(),100)},[open]);

  const send=async(text)=>{
    const q=text||input.trim();if(!q||loading)return;
    setInput("");
    setMsgs(prev=>[...prev,{role:"user",text:q}]);
    setLoading(true);
    const ctx=buildCtx(pg,contextData);
    try{
      const data=await apiPost("ai/insight",{context:ctx,question:q,history:msgs.slice(-6)});
      setMsgs(prev=>[...prev,{role:"ai",text:data.insight||"Không thể phân tích."}]);
    }catch(e){
      setMsgs(prev=>[...prev,{role:"ai",text:`Chưa kết nối AI (cần ANTHROPIC_API_KEY trong Railway).\n\nLỗi: ${e.message}`}]);
    }
    setLoading(false);
  };

  const renderMd=(text)=>text.split("\n").map((line,i)=>{
    if(line.startsWith("### "))return<div key={i} style={{fontSize:13.5,fontWeight:700,color:t.text,marginTop:10,marginBottom:3}}>{line.slice(4)}</div>;
    if(line.startsWith("## "))return<div key={i} style={{fontSize:14.5,fontWeight:700,color:t.primary,marginTop:12,marginBottom:4}}>{line.slice(3)}</div>;
    if(line.startsWith("# "))return<div key={i} style={{fontSize:15.5,fontWeight:800,color:t.text,marginTop:14,marginBottom:6}}>{line.slice(2)}</div>;
    if(line.match(/^[•\-\*]\s/))return<div key={i} style={{paddingLeft:14,position:"relative",marginBottom:3}}><span style={{position:"absolute",left:2}}>•</span>{line.replace(/^[•\-\*]\s/,"")}</div>;
    if(line.trim()==="")return<div key={i} style={{height:5}}/>;
    const parts=line.split(/\*\*(.*?)\*\*/g);
    if(parts.length>1)return<div key={i} style={{marginBottom:2}}>{parts.map((p,j)=>j%2===1?<strong key={j} style={{fontWeight:700,color:t.text}}>{p}</strong>:<span key={j}>{p}</span>)}</div>;
    return<div key={i} style={{marginBottom:2}}>{line}</div>;
  });

  const hints=AI_HINTS[pg]||AI_HINTS.exec;

  // Floating button
  if(!open)return<button onClick={()=>setOpen(true)} style={{position:"fixed",bottom:mob?60:20,right:16,zIndex:999,background:`linear-gradient(135deg,${t.primary},#5A6BC5)`,color:"#fff",border:"none",borderRadius:16,padding:"12px 20px",cursor:"pointer",boxShadow:"0 4px 20px rgba(59,74,138,.35)",fontSize:13.5,fontWeight:600,fontFamily:AI_FONT,display:"flex",alignItems:"center",gap:6,transition:"transform .2s"}} onMouseEnter={e=>e.currentTarget.style.transform="translateY(-2px)"} onMouseLeave={e=>e.currentTarget.style.transform=""}>AI Chat</button>;

  const W=mob?"100%":"420px";
  const H=mob?"100%":"70vh";

  return ReactDOM.createPortal(<>
    {/* Backdrop */}
    <div onClick={()=>setOpen(false)} style={{position:"fixed",inset:0,background:"rgba(0,0,0,.3)",zIndex:9998}}/>
    {/* Chat panel */}
    <div style={{position:"fixed",bottom:mob?0:20,right:mob?0:16,width:W,height:H,maxHeight:mob?"100vh":"70vh",zIndex:9999,background:t.card,borderRadius:mob?0:16,border:mob?"none":"1px solid "+t.cardBorder,boxShadow:"0 12px 40px "+t.shadow,display:"flex",flexDirection:"column",overflow:"hidden",fontFamily:AI_FONT}}>

      {/* Header */}
      <div style={{padding:"14px 16px",background:`linear-gradient(135deg,${t.primary},#5A6BC5)`,flexShrink:0}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div><div style={{fontSize:15,fontWeight:700,color:"#fff",fontFamily:AI_FONT}}>AI Assistant</div><div style={{fontSize:11,color:"rgba(255,255,255,.7)",marginTop:2,fontFamily:AI_FONT}}>Đang xem: {PG_LABEL[pg]||pg}</div></div>
          <button onClick={()=>setOpen(false)} style={{background:"rgba(255,255,255,.15)",border:"none",borderRadius:8,color:"#fff",cursor:"pointer",padding:"6px 10px",fontSize:13}}>✕</button>
        </div>
      </div>

      {/* Messages */}
      <div style={{flex:1,overflow:"auto",padding:"12px 16px"}}>
        {msgs.length===0&&!loading&&<div style={{textAlign:"center",padding:"24px 10px"}}>
          <div style={{fontSize:16,fontWeight:800,color:t.primary,marginBottom:8}}>AI</div>
          <div style={{fontSize:15,fontWeight:600,color:t.text,marginBottom:4}}>Hỏi bất cứ điều gì về data!</div>
          <div style={{fontSize:12.5,color:t.textMuted,lineHeight:1.6,marginBottom:14}}>AI sẽ phân tích dựa trên data trang {PG_LABEL[pg]||pg} đang hiển thị.</div>
          <div style={{display:"flex",flexDirection:"column",gap:6}}>{hints.map((h,i)=><button key={i} onClick={()=>send(h)} style={{padding:"10px 14px",borderRadius:10,border:"1px solid "+t.inputBorder,background:t.inputBg,color:t.textSec,fontSize:12.5,cursor:"pointer",textAlign:"left",fontFamily:AI_FONT,transition:"all .15s"}} onMouseEnter={e=>{e.currentTarget.style.borderColor=t.primary;e.currentTarget.style.color=t.primary}} onMouseLeave={e=>{e.currentTarget.style.borderColor=t.inputBorder;e.currentTarget.style.color=t.textSec}}>{h}</button>)}</div>
        </div>}

        {msgs.map((m,i)=><div key={i} style={{display:"flex",justifyContent:m.role==="user"?"flex-end":"flex-start",marginBottom:10}}>
          {m.role==="ai"&&<div style={{width:28,height:28,borderRadius:14,background:`linear-gradient(135deg,${t.primary},#5A6BC5)`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,flexShrink:0,marginRight:8,marginTop:2,color:"#fff"}}>AI</div>}
          <div style={{maxWidth:"80%",padding:"10px 14px",borderRadius:m.role==="user"?"14px 14px 4px 14px":"14px 14px 14px 4px",background:m.role==="user"?`linear-gradient(135deg,${t.primary},#5A6BC5)`:t.inputBg,color:m.role==="user"?"#fff":t.textSec,fontSize:13.5,lineHeight:1.7,fontFamily:AI_FONT}}>{m.role==="user"?m.text:renderMd(m.text)}</div>
        </div>)}

        {loading&&<div style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}>
          <div style={{width:28,height:28,borderRadius:14,background:`linear-gradient(135deg,${t.primary},#5A6BC5)`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,flexShrink:0,color:"#fff"}}>AI</div>
          <div style={{padding:"10px 14px",borderRadius:"14px 14px 14px 4px",background:t.inputBg}}>
            <div style={{display:"flex",gap:4}}>{[0,1,2].map(i=><div key={i} style={{width:7,height:7,borderRadius:"50%",background:t.textMuted,animation:`bounce .6s ${i*.15}s infinite alternate`}}/>)}</div>
            <style>{`@keyframes bounce{from{opacity:.3;transform:translateY(0)}to{opacity:1;transform:translateY(-4px)}}`}</style>
          </div>
        </div>}
        <div ref={endRef}/>
      </div>

      {/* Input */}
      <div style={{padding:"10px 14px",borderTop:"1px solid "+t.divider,flexShrink:0,display:"flex",gap:8,alignItems:"center"}}>
        <input ref={inputRef} value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send()}}} placeholder="Nhập câu hỏi..." style={{flex:1,padding:"11px 14px",borderRadius:12,border:"1px solid "+t.inputBorder,background:t.inputBg,color:t.text,fontSize:13.5,fontFamily:AI_FONT,outline:"none",boxSizing:"border-box"}}/>
        <button onClick={()=>send()} disabled={loading||!input.trim()} style={{width:36,height:36,borderRadius:12,border:"none",background:(!loading&&input.trim())?t.primary:t.inputBorder,color:(!loading&&input.trim())?"#fff":t.textMuted,cursor:(!loading&&input.trim())?"pointer":"default",fontSize:14,flexShrink:0,display:"flex",alignItems:"center",justifyContent:"center"}}>➤</button>
      </div>
    </div>
  </>,document.body);
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
  const[asinF,setAsinF]=useState("All");
  const[planYear,setPlanYear]=useState(String(new Date().getFullYear()));
  const planYearOpts=useMemo(()=>{const c=new Date().getFullYear();return[String(c-1),String(c),String(c+1)]},[]);
  const clearDates=()=>{if(dbRange?.defaultStart)setSd(dbRange.defaultStart);else setSd(defaultStart);setEd(defaultEnd);setActivePeriod(null)};

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
  const[invFeeMonthly,setInvFeeMonthly]=useState([]);
  const[planKpiState,setPlanKpiState]=useState({gp:{a:0,p:0},np:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}});
  const[monthPlanState,setMonthPlanState]=useState([]);
  const[asinPlanBkState,setAsinPlanBkState]=useState([]);
  const[masterList,setMasterList]=useState([]);
  const[loading,setLoading]=useState(false);

  const opts=useBidirectionalFilters(store,seller,asinF,masterList);
  useEffect(()=>{if(store!=="All"&&opts.stores.length&&!opts.stores.includes(store))setStore("All")},[opts.stores]);
  useEffect(()=>{if(seller!=="All"&&opts.sellers.length&&!opts.sellers.includes(seller))setSeller("All")},[opts.sellers]);
  useEffect(()=>{if(asinF!=="All"&&opts.asins.length&&!opts.asins.includes(asinF))setAsinF("All")},[opts.asins]);

  // ═══════════ INIT: Connect to backend ═══════════
  const[filterError,setFilterError]=useState(null);
  useEffect(()=>{
    (async()=>{
      try{
        const ok=await checkBackend();setLive(ok);
        if(ok){
          try{
            const f=await api("filters");
            console.log("RAW filters response:",JSON.stringify(f).slice(0,500));
            if(f){
              const ml=[];
              const shopNames=(f.shops||[]).map(s=>s.shop||s.name).filter(Boolean);
              console.log("Shop names from API:",shopNames);
              if(f.asins){
                f.asins.forEach(a=>{
                  const shops=a.shops&&a.shops.length?a.shops:shopNames.length?[shopNames[0]]:["Unknown"];
                  shops.forEach(sh=>ml.push({a:a.asin||"",st:sh,sl:a.seller||""}));
                });
              }
              shopNames.forEach(sh=>{if(!ml.some(x=>x.st===sh))ml.push({a:"",st:sh,sl:""});});
              setMasterList(ml);
              console.log("masterList built:",ml.length,"entries. Sample:",ml.slice(0,3));
              if(ml.length===0)setFilterError("Filters API returned data but masterList is empty");
            }else{
              setFilterError("Filters API returned null/empty");
            }
          }catch(filterErr){
            console.error("FILTER API ERROR:",filterErr);
            setFilterError("Filter API error: "+filterErr.message);
          }
          const dr=await api("date-range").catch(()=>null);
          if(dr){
            setDbRange(dr);
            // End date = always today, start = 30 days ago (or dr.defaultStart)
            if(dr.defaultStart){
              console.log("Setting dates: start=",dr.defaultStart,"end=today (DB min:",dr.minDate,"max:",dr.maxDate,")");
              setSd(dr.defaultStart);
              // ed stays as today (defaultEnd)
            }
          }
          api("inventory/snapshot",{store}).then(d=>setInvData(d||{})).catch(()=>{});
          api("inventory/by-shop",{store}).then(d=>setInvShop((d||[]).map(r=>({s:r.shop,fba:r.fbaStock||0,inb:r.inbound||0,res:r.reserved||0,crit:r.criticalSkus||0,st:r.sellThrough||0,doh:r.daysOfSupply||0})))).catch(()=>{});
          api("inventory/stock-trend",{store}).then(d=>setInvTrend((d||[]).map(r=>{const dt=new Date(r.date);return{d:MS[dt.getMonth()]+" "+dt.getDate(),v:parseInt(r.fbaStock)||0}}))).catch(()=>{});
          api("inventory/storage-monthly",{store}).then(d=>setInvFeeMonthly(d||[])).catch(()=>{});
        }
      }catch(e){console.error("INIT ERROR:",e)}
      setDbConnecting(false);
    })();
  },[]);

  // ═══════════ FETCH DATA when filters/dates change ═══════════
  // Debounced fetch: wait 400ms after last filter change before fetching
  const [fetchTrigger,setFetchTrigger]=useState(0);
  const fetchParamsRef=useRef({sd,ed,store,seller,asinF});
  fetchParamsRef.current={sd,ed,store,seller,asinF};
  useEffect(()=>{
    if(!live||dbConnecting)return;
    const timer=setTimeout(()=>setFetchTrigger(t=>t+1),400);
    return()=>clearTimeout(timer);
  },[sd,ed,store,seller,asinF,live,dbConnecting]);
  useEffect(()=>{
    if(!live||dbConnecting||fetchTrigger===0)return;
    let cancelled=false;
    const{sd:_sd,ed:_ed,store:_st,seller:_sl,asinF:_af}=fetchParamsRef.current;
    const p={start:_sd,end:_ed,store:_st,seller:_sl,asin:_af};
    setLoading(true);setFilterError(null);
    const days=Math.max(1,Math.round((new Date(_ed)-new Date(_sd))/86400000)+1);
    const pe=new Date(new Date(_sd+"T00:00:00").getTime()-86400000);
    const ps=new Date(pe.getTime()-(days-1)*86400000);
    // Batch 1: critical data (summary + daily)
    const arr=v=>Array.isArray(v)?v:[];
    (async()=>{try{
      const[summary,daily]=await Promise.all([
        api("exec/summary",p).catch(e=>{setFilterError(prev=>(prev?prev+' | ':'')+'Exec: '+e.message);return EMPTY_EM;}),
        api("exec/daily",p).catch(e=>{console.error("exec/daily FAIL:",e);setFilterError(prev=>(prev?prev+" | ":"")+"Daily: "+e.message);return[];}),
      ]);
      if(cancelled)return;
      setEm(summary&&summary.sales!=null?summary:EMPTY_EM);
      setFDaily(arr(daily).map(r=>{const ds=String(r.date).slice(0,10);const dt=new Date(ds+"T12:00:00");const label=isNaN(dt)?ds:MS[dt.getMonth()]+" "+dt.getDate();return{date:r.date,label,revenue:parseFloat(r.revenue)||0,netProfit:parseFloat(r.netProfit)||0,units:parseInt(r.units)||0}}));
      // Batch 2: secondary data + prev period (non-blocking)
      const[prev,asins,shops,team]=await Promise.all([
        api("exec/summary",{...p,start:ps.toISOString().slice(0,10),end:pe.toISOString().slice(0,10)}).catch(()=>null),
        api("product/asins",{start:_sd,end:_ed,store:_st,seller:_sl,asin:_af}).catch(()=>[]),
        api("shops",{start:_sd,end:_ed,store:_st,seller:_sl,asin:_af}).catch(()=>[]),
        api("team",{start:_sd,end:_ed,seller:_sl,store:_st,asin:_af}).catch(e=>{setFilterError(prev=>(prev?prev+' | ':'')+'Team: '+e.message);return[];}),
      ]);
      if(cancelled)return;
      setPrevEm(prev&&prev.sales?prev:null);
      setFAsin(arr(asins).map(r=>({a:r.asin,b:r.shop||r.brand||"",st:r.shop||r.brand||"",sl:r.seller||"",r:parseFloat(r.revenue)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,u:parseInt(r.units)||0,cr:Math.round((parseFloat(r.cr)||0)*100)/100,ac:Math.round((parseFloat(r.acos)||0)*100)/100,ro:parseFloat(r.acos)>0?(100/parseFloat(r.acos)):0})));
      setFShopData(arr(shops).map(r=>({s:r.shop,r:parseFloat(r.revenue)||0,gp:parseFloat(r.grossProfit)||parseFloat(r.netProfit)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,f:parseInt(r.fbaStock)||0,o:parseInt(r.orders)||0,u:parseInt(r.units)||0,ad:parseFloat(r.ads)||0,sv:parseFloat(r.stockValue)||0,gpP:parseFloat(r.gpPlan)||0,rvP:parseFloat(r.rvPlan)||0,adP:parseFloat(r.adPlan)||0,unP:parseFloat(r.unPlan)||0})));
      setFSeller(arr(team).map(r=>({sl:r.seller,r:parseFloat(r.revenue)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,u:parseInt(r.units)||0,as:parseInt(r.asinCount)||0})));
    }catch(e){console.error("Fetch error:",e)}
    // Re-fetch inventory when store changes
    if(!cancelled){
      api("inventory/snapshot",{store:_st}).then(d=>{if(!cancelled)setInvData(d||{})}).catch(()=>{});
      api("inventory/by-shop",{store:_st}).then(d=>{if(!cancelled)setInvShop((d||[]).map(r=>({s:r.shop,fba:r.fbaStock||0,inb:r.inbound||0,res:r.reserved||0,crit:r.criticalSkus||0,st:r.sellThrough||0,doh:r.daysOfSupply||0})))}).catch(()=>{});
      api("inventory/stock-trend",{store:_st}).then(d=>{if(!cancelled)setInvTrend((d||[]).map(r=>{const dt=new Date(r.date);return{d:MS[dt.getMonth()]+" "+dt.getDate(),v:parseInt(r.fbaStock)||0}}))}).catch(()=>{});
      api("inventory/storage-monthly",{store:_st}).then(d=>{if(!cancelled)setInvFeeMonthly(d||[])}).catch(()=>{});
    }
    if(!cancelled)setLoading(false);})();
    return()=>{cancelled=true};
  },[fetchTrigger]);

  // ═══════════ FETCH PLAN DATA (debounced) ═══════════
  const [planTrigger,setPlanTrigger]=useState(0);
  const planParamsRef=useRef({planYear,store,seller,asinF});
  planParamsRef.current={planYear,store,seller,asinF};
  useEffect(()=>{
    if(!live||dbConnecting)return;
    const timer=setTimeout(()=>setPlanTrigger(t=>t+1),400);
    return()=>clearTimeout(timer);
  },[planYear,store,seller,asinF,live,dbConnecting]);
  useEffect(()=>{
    if(!live||dbConnecting||planTrigger===0)return;
    let cancelled=false;
    const{planYear:_py,store:_st,seller:_sl,asinF:_af}=planParamsRef.current;
    (async()=>{
      try{
        const[planRes,actualsRes]=await Promise.all([
          api("plan/data",{year:_py,store:_st,seller:_sl,asin:_af},60000).catch(e=>{console.error("plan/data ERROR:",e.message);setFilterError(prev=>(prev?prev+' | ':'')+'Plan: '+e.message);return null;}),
          api("plan/actuals",{year:_py,store:_st,seller:_sl,asin:_af},90000).catch(e=>{console.error("plan/actuals ERROR:",e.message);setFilterError(prev=>(prev?prev+' | ':'')+'Actuals: '+e.message);return null;})
        ]);
        console.log("plan/data:",JSON.stringify(planRes).slice(0,300));
        console.log("plan/actuals monthly:",actualsRes?.monthly?.length,"rows","debug:",actualsRes?._debug);
        if(cancelled)return;
        const plan=planRes||{};const actuals=actualsRes||{};
        const monthlyPlan=plan.monthlyPlan||{};const asinPlan=plan.asinPlan||{};
        const monthlyActuals=actuals.monthly||[];const asinBk=actuals.asinBreakdown||[];

        // Build planKpi: merge plan totals with actual totals
        const pk=plan.kpi||{gp:{a:0,p:0},np:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}};
        if(!pk.np)pk.np={a:0,p:0};
        // Fill actuals into kpi
        const aT={rv:0,gp:0,np:0,ad:0,un:0,se:0,im:0,cr:[],ct:[]};
        monthlyActuals.forEach(m=>{aT.rv+=m.ra||0;aT.gp+=m.gpa||0;aT.np+=m.npa||0;aT.ad+=m.aa||0;aT.un+=m.ua||0;aT.se+=m.sa||0;aT.im+=m.ia||0;if(m.cra)aT.cr.push(m.cra);if(m.cta)aT.ct.push(m.cta);});
        pk.rv.a=aT.rv;pk.gp.a=aT.gp;pk.np.a=aT.np;pk.ad.a=aT.ad;pk.un.a=aT.un;pk.se.a=aT.se;pk.im.a=aT.im;
        // CR = total Units / total Sessions (weighted, like PBI)
        pk.cr.a=aT.se>0?aT.un/aT.se:0;
        // CTR = average of monthly CTRs (since we don't have total clicks)
        pk.ct.a=aT.ct.length?aT.ct.reduce((s,v)=>s+v,0)/aT.ct.length:0;
        setPlanKpiState(pk);

        // Build monthPlanData: merge plan + actuals per month
        const mpd=MS.map((mName,i)=>{
          const mn=i+1;const pp=monthlyPlan[mn]||{};const aa=monthlyActuals.find(m=>m.mn===mn)||{};
          // Plan CR/CTR: use weighted values (crW/ctW) from server, or fallback (auto-detect ratio vs %)
          const planCr = pp.crW != null ? pp.crW : (pp.cr ? (pp.cr > 1 ? pp.cr/100 : pp.cr) : 0);
          const planCtr = pp.ctW != null ? pp.ctW : (pp.ct ? (pp.ct > 1 ? pp.ct/100 : pp.ct) : 0);
          // Store CR/CTR as percentages for display (ratio * 100)
          return{m:mName,gpa:aa.gpa||0,gpp:pp.gp||0,npa:aa.npa||0,npp:pp.np||0,ra:aa.ra||0,rp:pp.rv||0,aa:aa.aa||0,ap:pp.ad||0,ua:aa.ua||0,up:pp.un||0,sa:aa.sa||0,sp:pp.se||0,ia:aa.ia||0,ip:pp.im||0,cra:Math.round((aa.cra||0)*10000)/100,crp:Math.round(planCr*10000)/100,cta:Math.round((aa.cta||0)*10000)/100,ctp:Math.round(planCtr*10000)/100};
        });
        setMonthPlanState(mpd);

        // Build asinBreakdown: merge plan + actuals per ASIN with per-month data
        const allAsins=new Set([...Object.keys(asinPlan),...asinBk.map(a=>a.a)]);
        const abk=[...allAsins].map(asin=>{
          const pd=asinPlan[asin]||{brand:"",months:{}};const ad=asinBk.find(a=>a.a===asin)||{};
          // Sum plan across months
          let pTot={rv:0,gp:0,np:0,ad:0,un:0,se:0,im:0,cr:[],ct:[]};
          Object.values(pd.months||{}).forEach(m=>{pTot.rv+=m.rv||0;pTot.gp+=m.gp||0;pTot.np+=m.np||0;pTot.ad+=m.ad||0;pTot.un+=m.un||0;pTot.se+=m.se||0;if(m.cr)pTot.cr.push(m.cr);});
          const crP=pTot.se>0&&pTot.un>0?Math.round(pTot.un/pTot.se*10000)/100:(pTot.cr.length?pTot.cr.reduce((s,v)=>s+v,0)/pTot.cr.length:0);
          // Build per-month merged data
          const allMonths=new Set([...Object.keys(pd.months||{}),...Object.keys(ad.months||{})]);
          const mData={};
          allMonths.forEach(mn=>{
            const pm=pd.months?.[mn]||{};const am=ad.months?.[mn]||{};
            const planCrM=pm.un&&pm.se?Math.round(pm.un/pm.se*10000)/100:(pm.cr?pm.cr>1?pm.cr:Math.round(pm.cr*10000)/100:0);
            const planCtM=pm.se&&pm.im?Math.round(pm.se/pm.im*10000)/100:(pm.ct?pm.ct>1?pm.ct:Math.round(pm.ct*10000)/100:0);
            mData[mn]={ra:am.rv||0,rp:pm.rv||0,ga:am.gp||0,gp:pm.gp||0,na:am.np||0,np:pm.np||0,aa:am.ad||0,ap:pm.ad||0,ua:am.un||0,up:pm.un||0,sa:am.se||0,sp:pm.se||0,ia:am.im||0,ip:pm.im||0,sv:am.sv||0,cra:Math.round((am.cr||0)*10000)/100,crp:planCrM,cta:Math.round((am.ct||0)*10000)/100,ctp:planCtM};
          });
          return{a:asin,br:pd.brand||ad.br||"",sl:ad.sl||"",ga:ad.ga||0,gp:pTot.gp,na:ad.na||0,np:pTot.np,ra:ad.ra||0,rp:pTot.rv,aa:ad.aa||0,ap:pTot.ad,ua:ad.ua||0,up:pTot.un,sa:ad.sa||0,sp:pTot.se,ia:ad.ia||0,ip:pTot.im,sv:parseFloat(ad.sv)||0,cra:Math.round((ad.cra||0)*10000)/100,crp:crP,cta:Math.round((ad.cta||0)*10000)/100,ctp:0,mData};
        }).sort((a,b)=>(b.ga||0)-(a.ga||0));
        setAsinPlanBkState(abk);
      }catch(e){console.error("Plan fetch error:",e)}
    })();
    return()=>{cancelled=true};
  },[planTrigger]);

  const fShopRev=useMemo(()=>fShopData.map(s=>({s:s.s,r:s.r,n:s.n})),[fShopData]);

  const pctChg=useCallback((cur,prev)=>{if(prev==null||prev===0)return undefined;return((cur-prev)/Math.abs(prev))*100},[]);

  // Filter visibility per page
  // Filter visibility: Exec=Brand+Seller, Plan=Brand+Seller+ASIN, Prod/Shop/Team/Daily=Store+Seller+ASIN, Inv=Store
  // "Brand" = same as Store (account.shop), just different label
  const showShopFilter=["exec","prod","shops","team","daily","inv","plan"].includes(pg);
  const shopLabel="All Shops";
  const showSeller=["exec","prod","shops","team","plan","daily"].includes(pg);
  const showAsin=["plan","prod","shops","team","daily"].includes(pg);

  if(dbConnecting)return<div style={{display:"flex",alignItems:"center",justifyContent:"center",height:"100vh",background:t.bg}}><Spinner t={t} text="Connecting..."/></div>;

  return<div style={{display:"flex",flexDirection:mob?"column":"row",height:"100vh",background:t.bg,fontFamily:"'DM Sans',system-ui,-apple-system,sans-serif",color:t.text,overflow:"hidden",transition:"background .3s"}}>
    {/* SIDEBAR (desktop) or BOTTOM NAV (mobile) */}
    {!mob&&<div style={{width:(tab||!sb)?56:220,background:t.sidebar,borderRight:"1px solid "+t.sidebarBorder,display:"flex",flexDirection:"column",transition:"width .2s",flexShrink:0,overflow:"hidden"}}>
      <div style={{padding:"16px 14px 12px",display:"flex",alignItems:"center",gap:10,borderBottom:"1px solid "+t.sidebarBorder,minHeight:54}}><div style={{width:34,height:34,borderRadius:10,background:"linear-gradient(135deg,#3B4A8A,#6B7FD7)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:15,fontWeight:800,color:"#fff",flexShrink:0,boxShadow:"0 2px 8px rgba(59,74,138,.3)"}}>A</div>{!tab&&sb&&<div><div style={{fontSize:15,fontWeight:800,color:t.text,lineHeight:1.1,letterSpacing:-.3}}>Amazon</div><div style={{fontSize:8.5,color:t.textMuted,letterSpacing:2,fontWeight:700,textTransform:"uppercase",marginTop:1}}>Dashboard</div></div>}</div>
      <div style={{flex:1,padding:6,overflowY:"auto"}}>{NAV.map(n=><button key={n.id} onClick={()=>setPg(n.id)} style={{width:"100%",display:"flex",alignItems:"center",padding:(!tab&&sb)?"11px 16px":"11px 0",borderRadius:10,border:"none",cursor:"pointer",marginBottom:2,background:pg===n.id?t.sidebarActive:"transparent",color:pg===n.id?t.primary:t.textSec,justifyContent:(!tab&&sb)?"flex-start":"center",fontSize:13.5,transition:"all .15s ease"}} onMouseEnter={e=>{if(pg!==n.id)e.currentTarget.style.background=t.tableHover}} onMouseLeave={e=>{if(pg!==n.id)e.currentTarget.style.background="transparent"}}>{(!tab&&sb)?<span style={{fontWeight:pg===n.id?700:500,whiteSpace:"nowrap",letterSpacing:-.1}}>{n.l}</span>:<span style={{fontSize:10,fontWeight:700,letterSpacing:-.5}}>{n.l.split(" ")[0].slice(0,3)}</span>}</button>)}</div>
      {!tab&&<div style={{padding:6,borderTop:"1px solid "+t.sidebarBorder}}><button onClick={()=>setSb(!sb)} style={{width:"100%",padding:"8px 12px",borderRadius:8,border:"none",cursor:"pointer",background:"transparent",color:t.textMuted,display:"flex",alignItems:"center",justifyContent:sb?"flex-start":"center",gap:6,fontSize:11,fontWeight:600}}><span>{sb?"◀":"▶"}</span>{sb&&<span>Collapse</span>}</button></div>}
    </div>}

    <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",paddingBottom:mob?56:0}}>
      {/* TOPBAR */}
      <div style={{background:t.topbar,borderBottom:"1px solid "+t.cardBorder,padding:mob?"10px 14px":"14px 24px",display:"flex",flexDirection:"column",gap:10,flexShrink:0}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>{mob&&<button onClick={()=>setMobileFilters(!mobileFilters)} style={{background:t.primaryLight,border:"1px solid "+t.primary+"33",borderRadius:10,padding:"7px 12px",cursor:"pointer",fontSize:12,color:t.primary,fontWeight:700}}>☰</button>}<span style={{fontSize:mob?17:20,fontWeight:800,color:t.text,letterSpacing:-.4}}>{cn?.l}</span></div>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            {loading&&<span style={{fontSize:9,color:t.orange,fontWeight:600}}>⏳</span>}
            <span style={{fontSize:9.5,fontWeight:700,padding:"4px 12px",borderRadius:10,background:live?"#EAFAF1":"#FFF8EC",color:live?"#1B8553":"#C67D1A",letterSpacing:.5}}>{live?"● Live DB":"○ No DB"}</span><span style={{fontSize:9,color:t.textMuted,marginLeft:4,fontWeight:600}}>v4.4</span>
            <button onClick={()=>setDark(!isDark)} style={{background:t.card,border:"1px solid "+t.inputBorder,borderRadius:10,padding:"6px 12px",cursor:"pointer",fontSize:13,color:t.textSec,transition:"all .15s"}} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background=t.card}>{isDark?"Light":"Dark"}</button>
          </div>
        </div>
        {/* FILTER BAR */}
        {(!mob||mobileFilters)&&<div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
          {["exec","prod","shops","team","daily"].includes(pg)&&<><DateInput label="Start" value={sd} onChange={v=>{setSd(v);setActivePeriod(null)}} t={t}/><DateInput label="End" value={ed} onChange={v=>{setEd(v);setActivePeriod(null)}} t={t}/><PeriodBtns onSelect={(s,e,l)=>{setSd(s);setEd(e);setActivePeriod(l)}} active={activePeriod} t={t} refDate={defaultEnd}/><ClearBtn onClick={clearDates} t={t}/></>}
          {pg==="plan"&&<><Sel value={planYear} onChange={setPlanYear} options={planYearOpts} label="All Years" t={t}/></>}
          {showShopFilter&&<Sel value={store} onChange={setStore} options={opts.stores} label={shopLabel} t={t}/>}
          {showSeller&&<Sel value={seller} onChange={setSeller} options={opts.sellers} label="All Sellers" t={t}/>}
          {showAsin&&<AsinSel value={asinF} onChange={setAsinF} options={opts.asins} label="All ASINs" t={t}/>}
        </div>}
      </div>

      {/* CONTENT */}
      <div style={{flex:1,overflow:"auto",padding:mob?12:20}}>
        {filterError&&<div style={{padding:"10px 16px",marginBottom:12,background:"#FEF3CD",border:"1px solid #F0D060",borderRadius:8,fontSize:11,color:"#856404"}}>Filter issue: {filterError} — <a href={window.location.origin+"/api/debug/filters"} target="_blank" rel="noopener" style={{color:"#0066CC",textDecoration:"underline"}}>View debug info</a></div>}
        {pg==="exec"&&<ExecPage t={t} fAsin={fAsin} fShop={fShopRev} fDaily={fDaily} em={em} sd={sd} ed={ed} prevEm={prevEm} pctChg={pctChg} mob={mob}/>}
        {pg==="inv"&&<InvPage t={t} mob={mob} invData={invData} invShop={invShop} invTrend={invTrend} invFeeMonthly={invFeeMonthly}/>}
        {pg==="plan"&&<PlanPage t={t} planKpi={planKpiState} monthPlanData={monthPlanState} asinPlanBkData={asinPlanBkState} seller={seller} store={store} asinF={asinF}/>}
        {pg==="prod"&&<ProdPage t={t} fAsin={fAsin} fDaily={fDaily}/>}
        {pg==="shops"&&<ShopPage t={t} fShopData={fShopData} fDaily={fDaily}/>}
        {pg==="team"&&<TeamPage t={t} fSeller={fSeller} fDaily={fDaily} asinPlanBkData={asinPlanBkState}/>}
        {pg==="daily"&&<OpsPage t={t} fDaily={fDaily} fShopData={fShopData}/>}
        <div style={{height:30}}/>
      </div>
    </div>

    {/* MOBILE BOTTOM NAV */}
    {mob&&<div style={{position:"fixed",bottom:0,left:0,right:0,background:t.sidebar,borderTop:"1px solid "+t.sidebarBorder,display:"flex",justifyContent:"space-around",padding:"8px 0",zIndex:998}}>{NAV.map(n=><button key={n.id} onClick={()=>{setPg(n.id);setMobileFilters(false)}} style={{display:"flex",flexDirection:"column",alignItems:"center",gap:2,background:"none",border:"none",cursor:"pointer",padding:"4px 6px",borderRadius:6,color:pg===n.id?t.primary:t.textMuted,fontSize:10,fontWeight:pg===n.id?700:500,minWidth:0}}><span style={{whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis",maxWidth:52}}>{n.l.split(" ")[0]}</span></button>)}</div>}

    <AiChat t={t} pg={pg} contextData={{em,fAsin,fShopData,fSeller,invData,invShop,fDaily,sd,ed}}/>
  </div>;
}
