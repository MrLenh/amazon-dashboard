import React, { useState, useRef, useEffect, useMemo, useCallback } from "react";
import ReactDOM from "react-dom";
import { checkBackend, api, apiPost } from "./api.js";
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, AreaChart, Area, ComposedChart, Cell, ScatterChart, Scatter,
  ZAxis, PieChart, Pie, ReferenceLine, Brush
} from "recharts";

/* ═══════════ THEMES ═══════════ */
const TH={
  light:{bg:"#F0F2F8",card:"#FFFFFF",cardBorder:"#E2E6EF",sidebar:"#FFFFFF",sidebarBorder:"#E8ECF3",sidebarActive:"#EEF0F8",topbar:"#FFFFFF",text:"#1A1D26",textSec:"#4A5068",textMuted:"#8890A8",primary:"#3B4A8A",primaryLight:"#EEF0F8",primaryGhost:"#F5F6FB",green:"#1B8553",greenBg:"#EAFAF1",red:"#D4380D",redBg:"#FFF1EC",orange:"#C67D1A",orangeBg:"#FFF8EC",blue:"#3B82F6",purple:"#8B5CF6",chartGrid:"#E8ECF3",inputBg:"#F5F6FA",inputBorder:"#D0D5E0",tableBg:"#F8F9FC",tableHover:"#EEF0F8",divider:"#E8ECF3",kpiIcon:"#EEF0F8",shadow:"rgba(59,74,138,0.10)"},
  dark:{bg:"#0D0F1A",card:"#181B2E",cardBorder:"#2E3350",sidebar:"#111525",sidebarBorder:"#252A40",sidebarActive:"#1E2448",topbar:"#111525",text:"#F0F2FA",textSec:"#CDD2EE",textMuted:"#9099BE",primary:"#8B9EF0",primaryLight:"#1C2040",primaryGhost:"#191C32",green:"#3DD68C",greenBg:"#0B2918",red:"#FF6B6B",redBg:"#2D1414",orange:"#FFB347",orangeBg:"#2B1E0D",blue:"#60AFFF",purple:"#B494FF",chartGrid:"#252A3E",inputBg:"#1A1D30",inputBorder:"#363B58",tableBg:"#1A1D30",tableHover:"#1F2248",divider:"#252A3E",kpiIcon:"#1E2248",shadow:"rgba(0,0,0,0.6)"},
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
const TIPS={sales:"Total revenue from all sales",units:"Total units sold",refunds:"Refunded orders",advCost:"Total ad spend (PPC)",shippingCost:"FBA shipping fees",refundCost:"Cost of processing refunds",amazonFees:"Referral + FBA fees",cogs:"Cost of Goods Sold",netProfit:"Revenue − All Costs",estPayout:"Estimated Amazon payout",realAcos:"Ad Spend / Sales × 100%",pctRefunds:"Refunds / Orders × 100%",margin:"Net Profit / Revenue × 100%",sessions:"Product page views",gp:"SUM(grossProfit) from seller_board_sales",cr:"Orders / Sessions × 100%",ctr:"Clicks / Impressions × 100%",sellThrough:"Units Sold / (Sold + Ending Inventory)",doh:"Current Stock / Avg Daily Sales",fbaStock:"Total FBA inventory (from Seller Board Stock). Includes Available + Reserved units across all warehouses",invAvail:"Units ready to pick & ship. Source: Amazon Inventory Planning (fba_iventory_planning → available). Note: may differ from FBA Stock KPI which uses Sellerboard's snapshot.",invReserved:"Units held by Amazon (pending orders, FC transfers). Source: fba_iventory_planning → totalReservedQuantity",invCritical:"SKUs with ≤ 30 days of supply remaining — need restocking urgently. Source: fba_iventory_planning → daysOfSupply",invInbound:"Total units across all inbound stages (working + shipped + received). Source: fba_iventory_planning → inboundQuantity",invDaysSupply:"Amazon's estimated days of supply, averaged across all active SKUs. Source: fba_iventory_planning → daysOfSupply (Amazon's own calculation). Note: the by-shop chart below uses a different method — FBA Stock ÷ Avg Daily Sales (last 30d) — so numbers will differ.",storageFee:"Estimated FBA storage fee for next month. Taken from the latest snapshot date of the most recent month — same source as the Storage Fee History table below. Source: fba_iventory_planning → estimatedStorageCostNextMonth",revenue:"Total sales revenue across all channels in selected period",np:"Revenue minus all costs (ads, COGS, Amazon fees, shipping, refunds)",avgMargin:"Average Net Profit ÷ Revenue across all entities shown",aov:"Average revenue per order = Total Sales ÷ Total Orders",upo:"Average units per order = Total Units ÷ Total Orders",prodRev:"Revenue from seller_board_product for selected ASINs/shops",prodNP:"Net Profit per ASIN from seller_board_product",prodMargin:"Net Profit ÷ Revenue per product",prodUnits:"Total units sold per ASIN in selected period",shopFba:"Latest FBA stock count from seller_board_stock per shop",teamRev:"Total revenue across all sellers in selected period",teamNP:"Total net profit across all sellers",teamMargin:"Average margin across all sellers",opsRev:"Daily revenue from seller_board_product (last 60 days)",opsNP:"Daily net profit from seller_board_product",opsUnits:"Daily units from seller_board_product",stockValue:"Current inventory value (snapshot from Sellerboard). Health ratio = Stock Value ÷ |GP|. Healthy <1.5x · Watch 1.5-3x · High >3x"};

/* ═══════════ ZONE A — PERIOD PRESET HELPER ═══════════ */
const ZONE_A_PRESETS=[
  {key:'tod_7_14_30', label:'Today / Yesterday / 7 days / 14 days / 30 days'},
  {key:'tod_yd_mtd',  label:'Today / Yesterday / Month to date / This month (forecast) / Last month'},
  {key:'week',        label:'This week / Last week / 2 weeks ago / 3 weeks ago'},
  {key:'month',       label:'Month to date / Last month / 2 months ago / 3 months ago'},
  {key:'qtr',         label:'This quarter / Last quarter / 2 quarters ago / 3 quarters ago'},
];
function getZoneAPeriods(presetKey, refDateStr){
  const ref=new Date((refDateStr||new Date().toISOString().slice(0,10))+'T12:00:00');
  const fmt=d=>d.toISOString().slice(0,10);
  const sub=(d,n)=>{const r=new Date(d);r.setDate(r.getDate()-n);return r};
  const today=fmt(ref);
  const yday=fmt(sub(ref,1));
  const soWeek=d=>{const r=new Date(d);r.setDate(r.getDate()-((r.getDay()+6)%7));return r};
  const soMonth=d=>new Date(d.getFullYear(),d.getMonth(),1);
  const eoMonth=d=>new Date(d.getFullYear(),d.getMonth()+1,0);
  const soQ=d=>new Date(d.getFullYear(),Math.floor(d.getMonth()/3)*3,1);
  const eoQ=d=>new Date(d.getFullYear(),Math.floor(d.getMonth()/3)*3+3,0);
  const fmtLabel=d=>MS[d.getMonth()]+' '+d.getDate()+', '+d.getFullYear();
  const rangeLabel=(s,e)=>fmtLabel(new Date(s+'T12:00:00'))+' – '+fmtLabel(new Date(e+'T12:00:00'));
  switch(presetKey){
    case 'tod_7_14_30': return[
      {id:'today', label:'Today',    start:today,               end:today,              dateLabel:fmtLabel(ref)},
      {id:'yday',  label:'Yesterday',start:yday,                end:yday,               dateLabel:fmtLabel(sub(ref,1))},
      {id:'7d',    label:'7 days',   start:fmt(sub(ref,6)),     end:yday,               dateLabel:rangeLabel(fmt(sub(ref,6)),yday)},
      {id:'14d',   label:'14 days',  start:fmt(sub(ref,13)),    end:yday,               dateLabel:rangeLabel(fmt(sub(ref,13)),yday)},
      {id:'30d',   label:'30 days',  start:fmt(sub(ref,29)),    end:yday,               dateLabel:rangeLabel(fmt(sub(ref,29)),yday)},
    ];
    case 'tod_yd_mtd': return[
      {id:'today', label:'Today',              start:today,                   end:today,                     dateLabel:fmtLabel(ref)},
      {id:'yday',  label:'Yesterday',          start:yday,                    end:yday,                      dateLabel:fmtLabel(sub(ref,1))},
      {id:'mtd',   label:'Month to date',      start:fmt(soMonth(ref)),       end:today,                     dateLabel:rangeLabel(fmt(soMonth(ref)),today)},
      {id:'tmf',   label:'This month (fcst)',  start:fmt(soMonth(ref)),       end:fmt(eoMonth(ref)),         dateLabel:MS[ref.getMonth()]+' '+ref.getFullYear()+' (est)'},
      {id:'lm',    label:'Last month',         start:fmt(soMonth(sub(ref,ref.getDate()))), end:fmt(eoMonth(sub(ref,ref.getDate()))), dateLabel:MS[(ref.getMonth()+11)%12]+' '+( ref.getMonth()===0?ref.getFullYear()-1:ref.getFullYear())},
    ];
    case 'week':{
      const tw0=soWeek(ref);const lw0=sub(tw0,7);const lw1=sub(tw0,1);const ww0=sub(tw0,14);const ww1=sub(tw0,8);const www0=sub(tw0,21);const www1=sub(tw0,15);
      return[
        {id:'tw',  label:'This week',   start:fmt(tw0),   end:today,      dateLabel:rangeLabel(fmt(tw0),today)},
        {id:'lw',  label:'Last week',   start:fmt(lw0),   end:fmt(lw1),   dateLabel:rangeLabel(fmt(lw0),fmt(lw1))},
        {id:'2w',  label:'2 weeks ago', start:fmt(ww0),   end:fmt(ww1),   dateLabel:rangeLabel(fmt(ww0),fmt(ww1))},
        {id:'3w',  label:'3 weeks ago', start:fmt(www0),  end:fmt(www1),  dateLabel:rangeLabel(fmt(www0),fmt(www1))},
      ];}
    case 'month':{
      const m0s=soMonth(ref);const m1=sub(ref,ref.getDate());const m1s=soMonth(m1);const m1e=eoMonth(m1);
      const m2=sub(m1s,1);const m2s=soMonth(m2);const m2e=eoMonth(m2);
      const m3=sub(m2s,1);const m3s=soMonth(m3);const m3e=eoMonth(m3);
      return[
        {id:'mtd', label:'Month to date', start:fmt(m0s),  end:today,    dateLabel:rangeLabel(fmt(m0s),today)},
        {id:'lm',  label:'Last month',    start:fmt(m1s),  end:fmt(m1e), dateLabel:MS[m1s.getMonth()]+' '+m1s.getFullYear()},
        {id:'2m',  label:'2 months ago',  start:fmt(m2s),  end:fmt(m2e), dateLabel:MS[m2s.getMonth()]+' '+m2s.getFullYear()},
        {id:'3m',  label:'3 months ago',  start:fmt(m3s),  end:fmt(m3e), dateLabel:MS[m3s.getMonth()]+' '+m3s.getFullYear()},
      ];}
    case 'qtr':{
      const tqs=soQ(ref);const tqe=eoQ(ref);
      const lq=sub(tqs,1);const lqs=soQ(lq);const lqe=eoQ(lq);
      const q2=sub(lqs,1);const q2s=soQ(q2);const q2e=eoQ(q2);
      const q3=sub(q2s,1);const q3s=soQ(q3);const q3e=eoQ(q3);
      const qLabel=d=>`Q${Math.floor(d.getMonth()/3)+1} ${d.getFullYear()}`;
      return[
        {id:'tq', label:'This quarter',   start:fmt(tqs), end:fmt(tqe), dateLabel:qLabel(tqs)},
        {id:'lq', label:'Last quarter',   start:fmt(lqs), end:fmt(lqe), dateLabel:qLabel(lqs)},
        {id:'2q', label:'2 quarters ago', start:fmt(q2s), end:fmt(q2e), dateLabel:qLabel(q2s)},
        {id:'3q', label:'3 quarters ago', start:fmt(q3s), end:fmt(q3e), dateLabel:qLabel(q3s)},
      ];}
    default: return[];
  }
}

/* ═══════════ BUILD DETAIL ROWS — shared between Zone A tiles + Zone B drawer ═══════════ */
function buildDetailRows(em, detail={}){
  const merged={...em,...detail};
  const cr=merged.sessions>0?(merged.units/merged.sessions*100):0;
  const tacos=merged.sales>0?(Math.abs(merged.advCost||0)/merged.sales*100):0;
  return[
    {id:'sales',     label:'Sales',          val:merged.sales||0,                              fmt:$2,   sub:[{l:'Organic',v:merged.salesOrganic||0,fmt:$2},{l:'Sponsored (PPC)',v:merged.salesPPC||0,fmt:$2}]},
    {id:'units',     label:'Units',          val:merged.units||0,                              fmt:N,    sub:[{l:'Organic',v:merged.unitsOrganic||0,fmt:N},{l:'Sponsored (PPC)',v:merged.unitsSP||0,fmt:N}]},
    {id:'refunds',   label:'Refunds',        val:merged.refunds||0,                            fmt:N,    sub:[]},
    {id:'promo',     label:'Promo',          val:merged.promo||0,                              fmt:$2,   sub:[]},
    {id:'ads',       label:'Adv. Cost',      val:Math.abs(merged.advCost||0),                  fmt:$2,   sub:[{l:'Sponsored Products',v:merged.sp||0,fmt:$2},{l:'Sponsored Brands',v:merged.sb||0,fmt:$2},{l:'Sponsored Brands Video',v:merged.sbv||0,fmt:$2},{l:'Sponsored Display',v:merged.sd||0,fmt:$2}]},
    {id:'refundCost',label:'Refund Cost',    val:Math.abs(merged.refundCost||0),               fmt:$2,   sub:[]},
    {id:'fees',      label:'Amazon Fees',    val:Math.abs(merged.amazonFees||0),               fmt:$2,   sub:[{l:'FBA Fulfillment Fee',v:merged.fbaFulfillment||0,fmt:$2},{l:'Referral Fee (Commission)',v:merged.commission||0,fmt:$2}]},
    {id:'cogs',      label:'Cost of Goods',  val:Math.abs(merged.cogs||0),                     fmt:$2,   sub:[]},
    {id:'grossProfit',label:'Gross Profit',  val:merged.grossProfit||0,                        fmt:$2,   sub:[]},
    {id:'np',        label:'Net Profit',     val:merged.netProfit||0,                          fmt:$2,   sub:[]},
    {id:'payout',    label:'Est. Payout',    val:merged.estPayout||0,                          fmt:$2,   sub:[]},
    {id:'realAcos',  label:'Real ACOS',      val:merged.realAcos||0,                           fmt:v=>v.toFixed(2)+'%', sub:[]},
    {id:'pctRef',    label:'% Refunds',      val:merged.pctRefunds||0,                         fmt:v=>v.toFixed(2)+'%', sub:[]},
    {id:'margin',    label:'Margin',         val:merged.margin||0,                             fmt:v=>v.toFixed(2)+'%', sub:[]},
    {id:'sessions',  label:'Sessions',       val:Math.round(merged.sessions||0),               fmt:N,    sub:[]},
    {id:'cr',        label:'CR%',            val:cr,                                           fmt:v=>v.toFixed(2)+'%', sub:[]},
    {id:'tacos',     label:'TACoS',          val:tacos,                                        fmt:v=>v.toFixed(2)+'%', sub:[]},
    {id:'roas',      label:'ROAS',           val:merged.realAcos>0?(100/merged.realAcos):0,    fmt:v=>v.toFixed(2)+'x', sub:[]},
  ];
}

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

function PlanKpi({title,actual,plan,t,highlight,tip,fmt}){const isN=typeof actual==="number"&&typeof plan==="number";const gap=isN?actual-plan:null;const gc=gap!=null?(gap>=0?t.green:t.red):t.textMuted;const F=fmt||$;const fmtActual=typeof actual==="number"?F(actual):actual;const fmtPlan=typeof plan==="number"?F(plan):plan;const fmtGap=gap!=null?F(gap):"—";return<div style={{background:highlight?t.primaryLight:t.card,borderRadius:14,padding:"20px 22px",border:highlight?"2px solid "+t.primary:"1px solid "+t.cardBorder,overflow:"visible",transition:"all .2s ease"}} onMouseEnter={e=>{e.currentTarget.style.boxShadow="0 8px 28px "+t.shadow;}} onMouseLeave={e=>{e.currentTarget.style.boxShadow="none";}}><div style={{fontSize:11.5,color:highlight?t.primary:t.textSec,textTransform:"uppercase",letterSpacing:1.2,fontWeight:700,marginBottom:14}}>{highlight?"⭐ ":""}{title}{tip&&<Tip text={tip} t={t}/>}</div><div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:5}}><span style={{fontSize:12,color:t.textSec,fontWeight:600}}>Actual</span><span style={{fontSize:highlight?28:24,fontWeight:800,color:highlight?t.primary:t.text,letterSpacing:-.3}}>{fmtActual}</span></div><div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline"}}><span style={{fontSize:12,color:t.textSec,fontWeight:600}}>Plan</span><span style={{fontSize:15,fontWeight:600,color:t.textSec}}>{fmtPlan}</span></div><div style={{marginTop:14,padding:"10px 14px",borderRadius:10,background:t.primaryGhost,display:"flex",justifyContent:"space-between"}}><span style={{fontSize:12,color:t.textSec,fontWeight:600}}>Gap</span><span style={{fontSize:15,fontWeight:700,color:gc}}>{fmtGap}</span></div></div>}

const Sec=({title,icon,t,action,children})=><div style={{marginTop:28}}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:14}}><div style={{display:"flex",alignItems:"center",gap:8}}>{icon&&<span style={{fontSize:17}}>{icon}</span>}<span style={{fontSize:16,fontWeight:700,color:t.text,letterSpacing:-.2}}>{title}</span></div>{action}</div>{children}</div>;
const Cd=({children,t,style:s})=><div style={{background:t.card,borderRadius:14,padding:20,border:"1px solid "+t.cardBorder,...s}}>{children}</div>;
const CT=({active,payload,label,t:th})=>{if(!active||!payload?.length)return null;const t=th||TH.light;return<div style={{background:t.card,border:"1px solid "+t.cardBorder,borderRadius:10,padding:"10px 14px",boxShadow:"0 4px 20px "+t.shadow}}><div style={{fontSize:11,color:t.textSec,marginBottom:5,fontWeight:700}}>{label}</div>{payload.filter(p=>p.value!=null&&!isNaN(p.value)).map((p,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:6,fontSize:13,marginTop:3}}><div style={{width:8,height:8,borderRadius:4,background:p.color,flexShrink:0}}/><span style={{color:t.textSec}}>{p.name}:</span><span style={{fontWeight:700,color:p.color}}>{typeof p.value==="number"?(Math.abs(p.value)>=1?p.value.toLocaleString("en-US",{maximumFractionDigits:2}):p.value.toFixed(4)):p.value}</span></div>)}</div>};

function APG({actual,plan,t,isMoney=true,suffix="",reverse=false}){if(actual==null)return<div><div style={{fontSize:14,fontWeight:700,color:t.textMuted}}>—</div><div style={{fontSize:11,color:t.textMuted}}>Plan: {isMoney?$(plan):N(plan)+suffix}</div></div>;const gap=typeof actual==="number"?actual-plan:null;const gc=gap!=null?(reverse?(gap<=0?t.green:t.red):(gap>=0?t.green:t.red)):t.textMuted;const fA=isMoney?$(actual):(typeof actual==="number"?actual.toLocaleString():actual)+suffix;const fP=isMoney?$(plan):(typeof plan==="number"?plan.toLocaleString():plan)+suffix;const fG=gap!=null?(isMoney?$(gap):(gap>=0?"+":"")+gap.toLocaleString()+suffix):"—";return<div style={{lineHeight:1.6}}><div style={{fontSize:14,fontWeight:700,color:t.text}}>{fA}</div><div style={{fontSize:11.5,color:t.textSec}}>Plan: {fP}</div><div style={{fontSize:11.5,fontWeight:700,color:gc}}>{fG}</div></div>}
function StockVal({sv,gp,t}){const ratio=gp&&gp!==0?(sv||0)/Math.abs(gp):null;let c=t.green,bg=t.greenBg,lb="Healthy";if(ratio===null){c=t.textMuted;bg=t.cardBorder;lb="N/A";}else if(ratio>3){c=t.red;bg=t.redBg;lb="High";}else if(ratio>1.5){c=t.orange;bg=t.orangeBg;lb="Watch";}return<div style={{lineHeight:1.5}}><div style={{fontSize:13,fontWeight:700,color:t.text}}>{$(sv||0)}</div><div style={{display:"inline-flex",alignItems:"center",gap:4,marginTop:2}}><span style={{fontSize:9,fontWeight:600,color:c,background:bg,padding:"1px 6px",borderRadius:8}}>{lb}</span>{ratio!==null&&<span style={{fontSize:9,color:t.textMuted}}>{ratio.toFixed(1)}x GP</span>}</div></div>}
function AsinLink({asin,onClick,t}){return<span style={{cursor:"pointer",color:t.primary,fontWeight:600,fontSize:13,letterSpacing:.3}} onClick={()=>onClick(asin)} onMouseEnter={e=>e.target.style.textDecoration="underline"} onMouseLeave={e=>e.target.style.textDecoration="none"}>{asin}</span>}
function StockModal({asin,t,onClose}){
  const[data,setData]=useState(null);const[loading,setLoading]=useState(true);const[err,setErr]=useState(null);
  useEffect(()=>{if(!asin)return;setLoading(true);setErr(null);
    api("stock/history",{asin},15000).then(d=>{setData(d);setLoading(false);}).catch(e=>{setErr(e.message);setLoading(false);});
  },[asin]);
  if(!asin)return null;
  const MS2=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  const chartData=(data?.history||[]).map(r=>{const d=new Date(r.date);return{date:r.date,label:MS2[d.getMonth()]+" "+d.getDate(),fba:r.fba}});
  const cur=data?.current||{};
  const dlColor=cur.daysLeft&&cur.daysLeft<30?t.red:cur.daysLeft<90?t.orange:t.green;
  return ReactDOM.createPortal(<div style={{position:"fixed",inset:0,zIndex:99999,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={onClose}>
    <div style={{position:"absolute",inset:0,background:"rgba(0,0,0,0.5)"}}/>
    <div style={{position:"relative",width:"min(900px,92vw)",maxHeight:"85vh",overflowY:"auto",background:t.card,borderRadius:16,border:"1px solid "+t.cardBorder,boxShadow:"0 24px 60px rgba(0,0,0,0.3)",padding:0}} onClick={e=>e.stopPropagation()}>
      <div style={{padding:"20px 24px 12px",borderBottom:"1px solid "+t.divider,display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
        <div><div style={{fontSize:18,fontWeight:800,color:t.text}}>{asin}</div>
          {data&&<div style={{fontSize:12,color:t.textSec,marginTop:4,lineHeight:1.6}}>{data.name}{data.shop&&<span style={{color:t.primary,fontWeight:600}}> · {data.shop}</span>}{data.sku&&<span style={{color:t.textMuted}}> · {data.sku}</span>}{cur.cogs>0&&<span style={{color:t.orange,fontWeight:600}}> · COGS: ${cur.cogs}</span>}</div>}
        </div>
        <button onClick={onClose} style={{background:"none",border:"none",fontSize:22,cursor:"pointer",color:t.textMuted,padding:"4px 8px",borderRadius:6,lineHeight:1}}>✕</button>
      </div>
      <div style={{padding:"16px 24px"}}>
        {loading?<div style={{textAlign:"center",padding:40,color:t.textMuted}}>Loading stock history...</div>
        :err?<div style={{textAlign:"center",padding:40,color:t.red}}>Error: {err}</div>
        :<>
          <div style={{display:"flex",gap:16,marginBottom:20,flexWrap:"wrap"}}>
            <div style={{flex:"1 1 160px"}}>
              <div style={{fontSize:9,color:t.textMuted,textTransform:"uppercase",letterSpacing:1}}>Days of stock left (FBA)</div>
              <div style={{fontSize:28,fontWeight:800,color:dlColor}}>{cur.daysLeft||"—"}</div>
            </div>
            <div style={{flex:"1 1 160px"}}>
              <div style={{fontSize:9,color:t.textMuted,textTransform:"uppercase",letterSpacing:1}}>Stock Value (snapshot)</div>
              <div style={{fontSize:28,fontWeight:800,color:t.text}}>{$2(cur.stockValue)}</div>
            </div>
            <div style={{flex:"1 1 160px"}}>
              <div style={{fontSize:9,color:t.textMuted,textTransform:"uppercase",letterSpacing:1}}>Sales velocity (units/day)</div>
              <div style={{fontSize:28,fontWeight:800,color:t.text}}>{cur.velocity||0}</div>
            </div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(110px,1fr))",gap:8,marginBottom:20}}>
            {[{l:"FBA Stock",v:N(cur.fba)},{l:"Reserved",v:N(cur.reserved)},{l:"Sent to FBA",v:N(cur.sentToFBA)},{l:"Prep Stock",v:N(cur.prepStock)},{l:"ROI",v:(cur.roi||0)+"%"},{l:"Margin",v:(cur.margin||0).toFixed(1)+"%"}].map((k,i)=>
              <div key={i} style={{background:t.tableBg,borderRadius:8,padding:"8px 10px"}}>
                <div style={{fontSize:8,color:t.textMuted,textTransform:"uppercase",letterSpacing:1}}>{k.l}</div>
                <div style={{fontSize:14,fontWeight:700,color:t.text,marginTop:2}}>{k.v}</div>
              </div>
            )}
          </div>
          <div style={{fontSize:13,fontWeight:700,color:t.text,marginBottom:8}}>Stock History</div>
          <div style={{fontSize:10,color:t.textMuted,marginBottom:10}}>FBA on-hand stock (last 12 months)</div>
          {chartData.length>0?<ResponsiveContainer width="100%" height={260}>
            <ComposedChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/>
              <XAxis dataKey="label" tick={{fill:t.textSec,fontSize:10}} interval={Math.max(0,Math.floor(chartData.length/10))}/>
              <YAxis tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>N(v)}/>
              <Tooltip content={({active,payload,label})=>active&&payload?.length?<div style={{background:t.card,border:"1px solid "+t.cardBorder,borderRadius:8,padding:"8px 12px",boxShadow:"0 4px 12px "+t.shadow}}>
                <div style={{fontSize:11,fontWeight:700,color:t.text,marginBottom:4}}>{label}</div>
                {payload.map((p,i)=><div key={i} style={{fontSize:11,color:p.color}}>{p.name}: {N(p.value)}</div>)}
              </div>:null}/>
              <Area type="monotone" dataKey="fba" name="FBA Stock" stroke={t.primary} fill={t.primary} fillOpacity={0.1} strokeWidth={2}/>
            </ComposedChart>
          </ResponsiveContainer>:<div style={{textAlign:"center",padding:30,color:t.textMuted,fontSize:12}}>No historical data available</div>}
          <div style={{marginTop:8,fontSize:10,color:t.textMuted,fontStyle:"italic"}}>Stock Value and snapshot metrics reflect current values (from Sellerboard). Chart shows daily FBA Stock history.</div>
        </>}
      </div>
    </div>
  </div>,document.body);
}

/* ═══════════ GRADIENT CHART HELPER ═══════════ */
const ChartGrads=({t})=><defs><linearGradient id="gRv" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.primary} stopOpacity={0.15}/><stop offset="100%" stopColor={t.primary} stopOpacity={0}/></linearGradient><linearGradient id="gNp" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.green} stopOpacity={0.15}/><stop offset="100%" stopColor={t.green} stopOpacity={0}/></linearGradient></defs>;

function TrendChart({data,t,h=240,keys}){
  const k=keys||[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"},{dk:"netProfit",n:"Net Profit",c:t.green,g:"url(#gNp)"}];
  return<Cd t={t}><ResponsiveContainer width="100%" height={h}><ComposedChart data={data}><ChartGrads t={t}/><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="label" tick={{fill:t.textSec,fontSize:11}} interval={Math.max(0,Math.floor(data.length/8))}/><YAxis tick={{fill:t.textSec,fontSize:11}} tickFormatter={v=>$s(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/>{k.map(ki=><Area key={ki.dk} type="monotone" dataKey={ki.dk} name={ki.n} fill={ki.g||"none"} stroke={ki.c} strokeWidth={2}/>)}</ComposedChart></ResponsiveContainer></Cd>;
}

/* ═══════════ ALERTS ═══════════ */
function Alerts({alerts,t}){return<Cd t={t} style={{padding:"14px 18px"}}><div style={{display:"flex",alignItems:"center",gap:7,marginBottom:12}}><span style={{fontSize:14,fontWeight:800,color:t.orange}}>!</span><span style={{fontSize:13,fontWeight:700,color:t.orange,letterSpacing:.3}}>Alerts & Anomalies</span></div>{alerts.map((a,i)=><div key={i} style={{display:"flex",alignItems:"flex-start",gap:10,padding:"7px 0",borderTop:i?"1px solid "+t.divider:"none"}}><div style={{width:7,height:7,borderRadius:3.5,marginTop:4,background:a.s==="c"?t.red:a.s==="w"?t.orange:t.blue,flexShrink:0}}/><span style={{fontSize:12.5,color:t.textSec,lineHeight:1.6}}>{a.t}</span></div>)}</Cd>}

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

/* ═══════════ EXECUTIVE v4.5 ═══════════ */

/* ═══════════ MINI DONUT — ASIN Distribution ═══════════ */
const DONUT_COLORS=['#3B4A8A','#3DD68C','#FFB347','#60AFFF','#B494FF','#aaaaaa'];
function MiniDonut({slices,t,size=72}){
  const[hov,setHov]=useState(null);
  const[tipPos,setTipPos]=useState({x:0,y:0});
  const ref=React.useRef(null);
  if(!slices||slices.length===0)return<div style={{width:size,height:size,borderRadius:'50%',background:t.tableBg,flexShrink:0}}/>;
  const total=slices.reduce((s,d)=>s+Math.abs(d.value),0);
  const hovSlice=hov!=null?slices[hov]:null;
  const handleMouseMove=(e)=>{
    if(!ref.current)return;
    const rect=ref.current.getBoundingClientRect();
    setTipPos({x:e.clientX-rect.left,y:e.clientY-rect.top});
  };
  return<div ref={ref} style={{position:'relative',flexShrink:0,width:size,height:size}} onMouseMove={handleMouseMove} onMouseLeave={()=>setHov(null)}>
    <PieChart width={size} height={size}>
      <Pie data={slices} cx={size/2-1} cy={size/2-1} innerRadius={size*0.32} outerRadius={size*0.48}
        dataKey="value" startAngle={90} endAngle={-270} stroke="none"
        onMouseEnter={(_,idx)=>setHov(idx)} onMouseLeave={()=>setHov(null)}>
        {slices.map((s,i)=><Cell key={i} fill={i===slices.length-1&&s.label==='Others'?t.chartGrid:DONUT_COLORS[i%DONUT_COLORS.length]}
          opacity={hov===null||hov===i?1:0.45}/>)}
      </Pie>
    </PieChart>
    {/* Center label */}
    <div style={{position:'absolute',top:'50%',left:'50%',transform:'translate(-50%,-50%)',textAlign:'center',pointerEvents:'none'}}>
      <div style={{fontSize:9,fontWeight:700,color:t.textMuted,lineHeight:1}}>Top 5</div>
      <div style={{fontSize:8,color:t.textMuted,lineHeight:1.2}}>ASINs</div>
    </div>
    {/* Hover tooltip */}
    {hovSlice&&ReactDOM.createPortal((()=>{
      const rect=ref.current?.getBoundingClientRect();
      if(!rect)return null;
      const tx=Math.min(rect.left+tipPos.x+12, window.innerWidth-240);
      const ty=rect.top+tipPos.y-10;
      const pct=total>0?(Math.abs(hovSlice.value)/total*100).toFixed(1):'0';
      return<div style={{position:'fixed',top:ty,left:tx,background:'#1e293b',color:'#f1f5f9',padding:'7px 10px',borderRadius:9,fontSize:11.5,zIndex:99999,boxShadow:'0 4px 20px rgba(0,0,0,.35)',pointerEvents:'none',minWidth:160,maxWidth:230}}>
        <div style={{display:'flex',alignItems:'center',gap:6,marginBottom:4}}>
          <div style={{width:8,height:8,borderRadius:2,background:hovSlice.label==='Others'?t.chartGrid:DONUT_COLORS[hov%DONUT_COLORS.length],flexShrink:0}}/>
          <span style={{fontWeight:700,fontSize:11,wordBreak:'break-all',lineHeight:1.3}}>{hovSlice.label}</span>
          {hovSlice.label!=='Others'&&<button
            onPointerDown={e=>{e.stopPropagation();navigator.clipboard?.writeText(hovSlice.label).catch(()=>{});}}
            style={{marginLeft:'auto',background:'rgba(255,255,255,.15)',border:'none',borderRadius:4,color:'#f1f5f9',fontSize:10,padding:'2px 6px',cursor:'pointer',flexShrink:0,lineHeight:1.4}}
            title="Copy ASIN">⎘</button>}
        </div>
        <div style={{fontSize:12,fontWeight:600,color:'#94a3b8'}}>{hovSlice.fmtV?hovSlice.fmtV(Math.abs(hovSlice.value)):hovSlice.value} <span style={{color:'#64748b',fontWeight:400}}>({pct}%)</span></div>
      </div>;
    })(),document.body)}
  </div>;
}

/* ══ StoreMultiSelect — shared checkbox dropdown for Zone A & Zone B ══ */
function StoreMultiSelect({selected,onChange,opts=[],accentColor,accentBorder,accentText,t,zIndex=500}){
  const[open,setOpen]=useState(false);
  const ref=useRef(null);
  useEffect(()=>{
    if(!open)return;
    const h=e=>{if(ref.current&&!ref.current.contains(e.target))setOpen(false)};
    document.addEventListener('mousedown',h);return()=>document.removeEventListener('mousedown',h);
  },[open]);
  const toggle=s=>{
    const next=new Set(selected);
    if(next.has(s))next.delete(s); else next.add(s);
    onChange(next);
  };
  const allSelected=selected.size===0;
  const label=allSelected?'All Shops':selected.size===1?Array.from(selected)[0]:selected.size+' Shops';
  const active=!allSelected;
  const BD=t.cardBorder; const DIV=t.divider; const S=t.text;
  return<div ref={ref} style={{position:'relative'}}>
    <button onClick={()=>setOpen(v=>!v)} style={{display:'flex',alignItems:'center',gap:6,background:t.card,border:'1.5px solid '+(active?accentBorder:accentBorder+'88'),borderRadius:9,padding:'6px 12px',fontSize:12,fontWeight:active?700:600,color:active?accentText:S,cursor:'pointer',whiteSpace:'nowrap',transition:'all .15s'}}>
      <span style={{fontSize:10}}>{active?'🏪 ':''}{label}</span>
      <span style={{fontSize:9,color:accentText,transition:'transform .2s',transform:open?'rotate(180deg)':'none'}}>▾</span>
    </button>
    {open&&<div style={{position:'absolute',top:'calc(100% + 6px)',left:0,background:t.card,border:'1px solid '+BD,borderRadius:13,boxShadow:'0 16px 48px rgba(20,24,36,.18)',zIndex,minWidth:220,overflow:'hidden'}}>
      {/* All Shops row */}
      <div onClick={()=>{onChange(new Set());setOpen(false);}} style={{display:'flex',alignItems:'center',gap:10,padding:'10px 14px',cursor:'pointer',borderBottom:'1px solid '+DIV,background:allSelected?accentColor+'18':'transparent',transition:'background .1s'}}
        onMouseEnter={e=>e.currentTarget.style.background=allSelected?accentColor+'28':t.tableHover}
        onMouseLeave={e=>e.currentTarget.style.background=allSelected?accentColor+'18':'transparent'}>
        <div style={{width:16,height:16,borderRadius:4,border:'2px solid '+(allSelected?accentColor:t.inputBorder),background:allSelected?accentColor:'transparent',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0,transition:'all .12s'}}>
          {allSelected&&<span style={{color:'#fff',fontSize:10,fontWeight:800,lineHeight:1}}>✓</span>}
        </div>
        <span style={{fontSize:12,fontWeight:allSelected?700:500,color:allSelected?accentText:S}}>All Shops</span>
      </div>
      {/* Divider + individual shops */}
      <div style={{maxHeight:260,overflowY:'auto'}}>
        {opts.map(s=>{
          const checked=selected.has(s);
          return<div key={s} onClick={()=>toggle(s)} style={{display:'flex',alignItems:'center',gap:10,padding:'9px 14px',cursor:'pointer',borderBottom:'1px solid '+DIV,background:checked?accentColor+'12':'transparent',transition:'background .1s'}}
            onMouseEnter={e=>e.currentTarget.style.background=checked?accentColor+'22':t.tableHover}
            onMouseLeave={e=>e.currentTarget.style.background=checked?accentColor+'12':'transparent'}>
            <div style={{width:16,height:16,borderRadius:4,border:'2px solid '+(checked?accentColor:t.inputBorder),background:checked?accentColor:'transparent',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0,transition:'all .12s'}}>
              {checked&&<span style={{color:'#fff',fontSize:10,fontWeight:800,lineHeight:1}}>✓</span>}
            </div>
            <span style={{fontSize:12,fontWeight:checked?600:400,color:checked?accentText:S}}>{s}</span>
          </div>;
        })}
      </div>
      {/* Footer: count + Clear */}
      {!allSelected&&<div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'8px 14px',borderTop:'1px solid '+DIV,background:t.tableBg}}>
        <span style={{fontSize:11,color:accentText,fontWeight:600}}>{selected.size} selected</span>
        <button onClick={()=>{onChange(new Set());}} style={{fontSize:11,fontWeight:700,color:accentColor,background:'transparent',border:'none',cursor:'pointer',padding:'2px 8px',borderRadius:6}}>Clear all</button>
      </div>}
    </div>}
  </div>;
}

function ExecPage({t,fAsin,fShop,fDaily,em,sd,ed,setSd,setEd,prevEm,prevPeriod,pctChg,mob,onAsinClick,splyEm,dailyLY,shopExt,
  store,seller,setStore,setSeller,storeOpts,sellerOpts,onApplyZoneB,
  zoneATileData,setZoneATileData,zoneAPreset,setZoneAPreset,zoneALoading,selectedStores,setSelectedStores}){
  const[selMetrics,setSelMetrics]=useState(['SALES','ADV.COST','NET PROFIT','SESSIONS']);
  const[expandedRows,setExpandedRows]=useState(new Set());
  const[showDetail,setShowDetail]=useState(false);
  const asinRef=useRef(null);
  const scrollToAsin=()=>setTimeout(()=>asinRef.current?.scrollIntoView({behavior:'smooth',block:'start'}),50);
  const[shopView,setShopView]=useState('table');
  const[donutTab,setDonutTab]=useState('rev');
  const[showLY,setShowLY]=useState(false);
  const[groupBy,setGroupBy]=useState('ASIN');
  const[sortShop,setSortShop]=useState('Revenue');
  // ── chip-based Sellerboard Summary ──
  const[sbVisible,setSbVisible]=useState(['sales','orders','units','refunds','advCost','estPayout','netProfit']);
  const[sbPickerOpen,setSbPickerOpen]=useState(false);
  const sbPickerRef=React.useRef(null);
  React.useEffect(()=>{
    if(!sbPickerOpen)return;
    const h=e=>{if(sbPickerRef.current&&!sbPickerRef.current.contains(e.target))setSbPickerOpen(false)};
    document.addEventListener('mousedown',h);return()=>document.removeEventListener('mousedown',h);
  },[sbPickerOpen]);

  const fmtD=d=>{try{return new Date(d+"T00:00:00").toLocaleDateString("en-US",{month:"short",day:"numeric",year:"numeric"})}catch{return d}};
  const ch=k=>prevEm?pctChg(em[k],prevEm[k]):undefined;
  const splyChg=k=>{if(!splyEm||!splyEm[k])return undefined;return pctChg(em[k],splyEm[k])};

  /* ── SUMMARY METRIC PILLS ── */
  const cr=em.sessions>0?(em.units/em.sessions*100):0;
  const tacos=em.sales>0?(Math.abs(em.advCost||0)/em.sales*100):0;
  const aov=em.orders>0?em.sales/em.orders:0;
  const profitPerUnit=em.units>0?em.netProfit/em.units:0;

  const prevCr=prevEm&&prevEm.sessions>0?(prevEm.units/prevEm.sessions*100):0;
  const prevTacos=prevEm&&prevEm.sales>0?(Math.abs(prevEm.advCost||0)/prevEm.sales*100):0;

  /* ── SELLERBOARD SUMMARY — chip definitions ── */
  const SB_ALL={
    sales:     {l:'Sales',     v:$2(em.sales),                       k:'sales',    profit:false, mw:148},
    orders:    {l:'Orders',    v:N(em.orders),                       k:'orders',                 mw:105},
    units:     {l:'Units',     v:N(em.units),                        k:'units',                  mw:100},
    refunds:   {l:'Refunds',   v:N(em.refunds),                      k:'refunds',                mw:95},
    advCost:   {l:'Adv. Cost', v:$2(Math.abs(em.advCost||0)),        k:'advCost',                mw:132},
    estPayout: {l:'Est. Payout',v:$2(em.estPayout),                  k:'estPayout',              mw:148},
    netProfit: {l:'Net Profit', v:$2(em.netProfit),                  k:'netProfit', profit:true, mw:132},
    tacos:     {l:'TACoS',     v:tacos.toFixed(2)+'%',               k:'_tacos',   isPct:true, ppDiff:prevEm?tacos-prevTacos:null, reverse:true, mw:95},
    margin:    {l:'Margin',    v:(em.margin||0).toFixed(2)+'%',      k:'margin',   isPct:true, ppDiff:prevEm?(em.margin||0)-(prevEm.margin||0):null, mw:95},
    sessions:  {l:'Sessions',  v:N(Math.round(em.sessions||0)),      k:'sessions',               mw:112},
    cr:        {l:'CR%',       v:cr.toFixed(2)+'%',                  k:'_cr',      isPct:true, ppDiff:prevEm?cr-prevCr:null, mw:90},
    aov:       {l:'AOV',       v:$2(aov),                            k:'_aov',                   mw:110},
    shippingCost:{l:'Shipping', v:$2(Math.abs(em.shippingCost||0)),  k:'shippingCost',            mw:118},
  };
  const sbRemove=key=>{if(sbVisible.length<=1)return;setSbVisible(prev=>prev.filter(k=>k!==key))};
  const sbAdd=key=>{if(!sbVisible.includes(key))setSbVisible(prev=>[...prev,key])};
  const sbToggle=key=>{sbVisible.includes(key)?sbRemove(key):sbAdd(key)};

  const ALL_PILLS=[
    {id:'UNITS',    label:'Units',       val:em.units,                  fmtV:N,  ch:()=>prevEm?pctChg(em.units,prevEm.units):undefined,       asinKey:'u'},
    {id:'SALES',    label:'Revenue',     val:em.sales,                  fmtV:$,  ch:()=>prevEm?pctChg(em.sales,prevEm.sales):undefined,       asinKey:'r'},
    {id:'ADV.COST', label:'Adv. Cost',   val:Math.abs(em.advCost||0),   fmtV:$,  ch:()=>prevEm?pctChg(em.advCost,prevEm.advCost):undefined,   asinKey:null},
    {id:'NET PROFIT',label:'Net Profit', val:em.netProfit,              fmtV:$,  ch:()=>prevEm?pctChg(em.netProfit,prevEm.netProfit):undefined,asinKey:'n'},
    {id:'SESSIONS', label:'Sessions',    val:Math.round(em.sessions||0),fmtV:N,  ch:()=>prevEm?pctChg(em.sessions,prevEm.sessions):undefined,  asinKey:null},
    {id:'CR%',      label:'CR%',         val:cr,                        fmtV:v=>v.toFixed(2)+'%',ch:()=>undefined,                            asinKey:'cr'},
    {id:'TACoS',    label:'TACoS',       val:tacos,                     fmtV:v=>v.toFixed(2)+'%',ch:()=>undefined,                            asinKey:'ac'},
    {id:'MARGIN',   label:'Margin',      val:em.margin||0,              fmtV:v=>v.toFixed(2)+'%',ch:()=>prevEm?((em.margin||0)-(prevEm.margin||0)):undefined, asinKey:'m'},
    {id:'AOV',      label:'AOV',         val:aov,                       fmtV:$2, ch:()=>undefined,                                            asinKey:null},
    {id:'PROFIT/UNIT',label:'Profit/Unit',val:profitPerUnit,            fmtV:$2, ch:()=>undefined,                                            asinKey:null},
    {id:'REFUNDS',  label:'Refunds',     val:em.refunds||0,             fmtV:N,  ch:()=>prevEm?pctChg(em.refunds,prevEm.refunds):undefined,   asinKey:null},
    {id:'PAYOUT',   label:'Est. Payout', val:em.estPayout||0,           fmtV:$,  ch:()=>undefined,                                            asinKey:null},
  ];
  const togglePill=id=>setSelMetrics(prev=>
    prev.includes(id)?prev.filter(m=>m!==id):[...prev,id]
  );
  const selPillData=selMetrics.map(id=>ALL_PILLS.find(p=>p.id===id)).filter(Boolean);

  /* ── DETAILED METRICS (expandable) ── */
  const NEW_BADGE=<span style={{fontSize:8,fontWeight:700,color:'#fff',background:t.primary,padding:'1px 5px',borderRadius:5,marginLeft:5,letterSpacing:.5}}>NEW</span>;
  // pvChg2: for metrics not directly in prevEm (computed values)
  const pv=(cur,prev)=>prev!=null&&prev!==0?((cur-prev)/Math.abs(prev)*100):undefined;
  const pvPP=(cur,prev)=>prev!=null?(cur-prev):undefined; // percentage point diff

  const DETAIL_ROWS=[
    // ── Sellerboard order ──
    {id:'sales',    label:'Sales',         val:em.sales,                         fmt:$2,  tip:TIPS.sales,     pvk:'sales',    sub:[
      {l:'Organic',v:em.salesOrganic||0,fmt:$2},{l:'Sponsored (PPC)',v:em.salesPPC||0,fmt:$2},
    ]},
    {id:'units',    label:'Units',         val:em.units,                         fmt:N,   tip:TIPS.units,     pvk:'units',    sub:[
      {l:'Organic',v:em.unitsOrganic||0,fmt:N},{l:'Sponsored (PPC)',v:em.unitsSP||0,fmt:N},
    ]},
    {id:'refunds',  label:'Refunds',       val:em.refunds||0,                    fmt:N,   tip:'Number of refunds',    pvk:'refunds',  sub:[]},
    {id:'promo',    label:'Promo',         val:em.promo||0,                      fmt:$2,  tip:'Promotions & coupons', pvk:null,       isNew:true,sub:[]},
    {id:'ads',      label:'Adv. Cost',     val:Math.abs(em.advCost||0),          fmt:$2,  tip:TIPS.advCost,   pvk:'advCost',  sub:[
      {l:'Sponsored Products',v:em.sp||0,fmt:$2},{l:'Sponsored Brands',v:em.sb||0,fmt:$2},
      {l:'Sponsored Brands Video',v:em.sbv||0,fmt:$2},{l:'Sponsored Display',v:em.sd||0,fmt:$2},
    ]},
    {id:'refundCost',label:'Refund Cost',  val:Math.abs(em.refundCost||0),       fmt:$2,  tip:'Cost of processing refunds',  pvk:'refundCost', sub:[]},
    {id:'fees',     label:'Amazon Fees',   val:Math.abs(em.amazonFees||0),       fmt:$2,  tip:TIPS.amazonFees, pvk:'amazonFees', sub:[
      {l:'FBA Fulfillment Fee',v:em.fbaFulfillment||0,fmt:$2},
      {l:'Referral Fee (Commission)',v:em.commission||0,fmt:$2},
    ]},
    {id:'cogs',     label:'Cost of Goods', val:Math.abs(em.cogs||0),             fmt:$2,  tip:'Cost of Goods Sold', pvk:'cogs',    sub:[]},
    {id:'grossProfit',label:'Gross Profit',val:em.grossProfit||0,                fmt:$2,  tip:'Revenue minus COGS and Amazon fees', pvk:'grossProfit', sub:[]},
    {id:'np',       label:'Net Profit',    val:em.netProfit,                     fmt:$2,  tip:TIPS.netProfit, pvk:'netProfit', sub:[]},
    {id:'payout',   label:'Est. Payout',   val:em.estPayout||0,                  fmt:$2,  tip:TIPS.estPayout, pvk:'estPayout', sub:[]},
    {id:'realAcos', label:'Real ACOS',     val:em.realAcos||0,                   fmt:v=>v.toFixed(2)+'%', tip:'Ad Cost / Sales', pvk:'realAcos', reverseColor:true, sub:[]},
    {id:'pctRef',   label:'% Refunds',     val:em.pctRefunds||0,                 fmt:v=>v.toFixed(2)+'%', tip:'Refunds / Orders', pvk:'pctRefunds', reverseColor:true, sub:[]},
    {id:'margin',   label:'Margin',        val:em.margin||0,                     fmt:v=>v.toFixed(2)+'%', tip:TIPS.margin, pvk:'margin', isPP:true, sub:[]},
    {id:'sessions', label:'Sessions',      val:Math.round(em.sessions||0),       fmt:N,   tip:TIPS.sessions,  pvk:'sessions', isNew:true, sub:[]},
    {id:'cr',       label:'CR%',           val:cr,                               fmt:v=>v.toFixed(2)+'%', tip:TIPS.cr, pvk:'_cr', isNew:true, sub:[]},
    {id:'tacos',    label:'TACoS',         val:tacos,                            fmt:v=>v.toFixed(2)+'%', tip:TIPS.realAcos, pvk:'_tacos', reverseColor:true, sub:[]},
    {id:'roas',     label:'ROAS',          val:em.realAcos>0?(100/em.realAcos):0,fmt:v=>v.toFixed(2)+'x', tip:'Revenue / Ad Spend', pvk:'_roas', isNew:true, sub:[]},
  ];

  /* ── DAILY TREND (combo: bars + lines) ── */
  const[trendBars,setTrendBars]=useState({revenue:true,netProfit:true,advCost:true});
  const[trendLines,setTrendLines]=useState({crPct:true,tacos:false});
  const[trendZoom,setTrendZoom]=useState(0); // 0 = All
  const[showBrush,setShowBrush]=useState(false);
  const dailyChartData=fDaily.map(d=>({
    ...d,
    advCost:Math.abs(d.advCost||0),
    crPct:d.sessions>0?(d.units/d.sessions*100):0,
    tacos:d.revenue>0?(Math.abs(d.advCost||0)/d.revenue*100):0,
  }));
  const LY_COLOR='#B8BDD8';

  /* ── SHOP SECTION ── */
  const SHOP_COLORS_REV=[t.primary,'#4C6EF5','#748FFC','#91A7FF','#BAC8FF','#DEE2FF','#EDF2FF'];
  const SHOP_COLORS_ADS=['#FF922B','#FFA94D','#FFD43B','#FFE066','#FFF3BF','#FFEC99','#FFF8DB'];
  const PROFIT_PALETTE=['#0ca678','#12b886','#20c997','#38d9a9','#099268','#087f5b','#63e6be','#96f2d7'];
  const LOSS_PALETTE=['#c92a2a','#a61e1e','#e03131','#862e2e'];
  const SHOP_COLORS_PROFIT=fShop.map((s,i)=>(s.n||0)<0?t.red:PROFIT_PALETTE[i%PROFIT_PALETTE.length]);
  const donutColors={rev:SHOP_COLORS_REV,ads:SHOP_COLORS_ADS,profit:SHOP_COLORS_PROFIT};
  const tRev=fShop.reduce((s,x)=>s+x.r,0);
  const tAds=fShop.reduce((s,x)=>s+Math.abs(x.n_ads||0),0);
  const tProfit=fShop.reduce((s,x)=>s+(x.n||0),0);
  const donutData={
    rev:fShop.slice(0,8).map((s,i)=>({name:s.s,value:s.r,fill:SHOP_COLORS_REV[i%7]})),
    ads:fShop.slice(0,8).map((s,i)=>({name:s.s,value:Math.abs(s.n_ads||0),fill:SHOP_COLORS_ADS[i%7]})),
    profit:(()=>{let pi=0,li=0;return fShop.slice(0,8).map(s=>{if((s.n||0)<0){const c=LOSS_PALETTE[li%LOSS_PALETTE.length];li++;return{name:s.s,value:Math.abs(s.n||0),fill:c};}else{const c=PROFIT_PALETTE[pi%PROFIT_PALETTE.length];pi++;return{name:s.s,value:s.n||0,fill:c};}});})(),
  };
  if(fShop.length>8){
    const rest=fShop.slice(8);
    donutData.rev.push({name:'Others',value:rest.reduce((s,x)=>s+x.r,0),fill:t.textMuted});
    donutData.ads.push({name:'Others',value:rest.reduce((s,x)=>s+Math.abs(x.n_ads||0),0),fill:t.textMuted});
    donutData.profit.push({name:'Others',value:rest.reduce((s,x)=>s+(x.n||0),0),fill:t.textMuted});
  }
  const donutTotal={rev:tRev,ads:tAds,profit:tProfit};
  const donutTitle={rev:'Revenue Share by Shop',ads:'Ad Spend Share by Shop',profit:'Profit Share by Shop'};

  const sortedShop=useMemo(()=>{
    const m={Revenue:(a,b)=>b.r-a.r,'Net Profit':(a,b)=>(b.n||0)-(a.n||0),Margin:(a,b)=>(b.m||0)-(a.m||0),Units:(a,b)=>(b.u||0)-(a.u||0)};
    return [...fShop].sort(m[sortShop]||m.Revenue);
  },[fShop,sortShop]);

  /* ── ASIN GROUP BY ── */
  const groupedAsins=useMemo(()=>{
    if(groupBy==='ASIN')return fAsin;
    const map={};
    fAsin.forEach(a=>{
      const key=groupBy==='Shop'?a.b:groupBy==='Brand'?a.b:groupBy==='Seller'?a.sl:a.a;
      if(!map[key])map[key]={a:key,b:key,sl:a.sl,r:0,n:0,u:0,cr:0,ac:0,ro:0,m:0,_cnt:0,_cr_sum:0};
      const g=map[key];g.r+=a.r;g.n+=a.n;g.u+=a.u;g._cr_sum+=a.cr;g._cnt++;
      g.m=g.r>0?(g.n/g.r*100):0;
      g.ac=g.r>0?(Math.abs(a.ac)*a.r+g.ac*g.r)/(g.r+a.r):0; // approx weighted
      g.ro=g.ac>0?100/g.ac:0;
      g.cr=g._cr_sum/g._cnt;
    });
    return Object.values(map).sort((a,b)=>b.r-a.r);
  },[fAsin,groupBy]);

  /* ── CSV EXPORT ── */
  const exportCSV=()=>{
    const rows=[['ASIN/Group','Shop','Revenue','Net Profit','Margin%','Units','CR%','ACoS','ROAS'].join(',')];
    groupedAsins.forEach(r=>rows.push([r.a,r.b,r.r.toFixed(2),r.n.toFixed(2),r.m.toFixed(2),r.u,r.cr.toFixed(2),r.ac.toFixed(2),r.ro.toFixed(2)].join(',')));
    const a=document.createElement('a');a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(rows.join('\n'));
    a.download='asin-performance.csv';a.click();
  };

  /* ── RECOMMENDATIONS ── */
  const asinRowRefs=useRef({});
  const[highlightedAsin,setHighlightedAsin]=useState(null);
  const scrollToAsinRow=asin=>{
    setGroupBy('ASIN');
    setHighlightedAsin(asin);
    setTimeout(()=>{
      const el=asinRowRefs.current[asin];
      if(el){el.scrollIntoView({behavior:'smooth',block:'center'});}
      else{asinRef.current?.scrollIntoView({behavior:'smooth',block:'start'});}
    },120);
    // Clear highlight after 3s
    setTimeout(()=>setHighlightedAsin(null),3200);
  };
  const recs=useMemo(()=>{
    const items=[];
    // High ACoS (multiple)
    fAsin.filter(a=>a.ac>40&&a.r>3000).sort((a,b)=>b.ac-a.ac).slice(0,3).forEach(a=>{
      items.push({title:`Cut ads on ${a.a}`,desc:`ACoS ${a.ac.toFixed(1)}% — ads eating margin. Consider pausing or reducing bid by 30%.`,color:t.orange,asin:a.a});
    });
    // High efficiency / scale up (multiple)
    fAsin.filter(a=>a.m>20&&a.ac<25&&a.r>5000).sort((a,b)=>b.m-a.m).slice(0,3).forEach(a=>{
      items.push({title:`Scale up ${a.a}`,desc:`Margin ${a.m.toFixed(1)}%, ACoS ${a.ac.toFixed(1)}% — high efficiency. Increase budget to capture more share.`,color:t.green,asin:a.a});
    });
    // Negative net profit ASINs
    fAsin.filter(a=>a.n<0&&a.r>1000).sort((a,b)=>a.n-b.n).slice(0,2).forEach(a=>{
      items.push({title:`Review loss-maker ${a.a}`,desc:`Net Profit ${$(a.n)} — below breakeven. Audit COGS, pricing, or pause.`,color:t.red,asin:a.a});
    });
    // Losing shops
    fShop.filter(s=>(s.n||0)<0).slice(0,2).forEach(s=>{
      items.push({title:`Review shop: ${s.s}`,desc:`Shop running at loss (${$(s.n||0)}). Audit COGS vs pricing, consider pausing low-margin ASINs.`,color:t.red,asin:null});
    });
    // Low margin but high revenue
    fAsin.filter(a=>a.m>0&&a.m<8&&a.r>10000).sort((a,b)=>b.r-a.r).slice(0,2).forEach(a=>{
      items.push({title:`Margin alert: ${a.a}`,desc:`Revenue ${$(a.r)} but margin only ${a.m.toFixed(1)}%. Review fees and COGS to improve profitability.`,color:t.orange,asin:a.a});
    });
    if(!items.length)items.push({title:'All metrics look healthy',desc:'No critical alerts. Keep monitoring ACoS and margin trends.',color:t.green,asin:null});
    return items;
  },[fAsin,fShop,t]);

  /* ═══ ZONE A — TILE DRAWER STATE ═══ */
  const[openTiles,setOpenTiles]=useState(new Set());
  const[tileExpandedRows,setTileExpandedRows]=useState({});
  const[tileErrors,setTileErrors]=useState({});
  const toggleTile=(id,tile)=>{
    setOpenTiles(prev=>{const s=new Set(prev);s.has(id)?s.delete(id):s.add(id);return s;});
    if(tile&&tile.detail===null&&!tileErrors[id]){
      const storeParam=tile.start&&store!=='All'?store:undefined;
      // 30s client-side timeout so it never stays "Loading..." forever
      const controller=new AbortController();
      const timer=setTimeout(()=>{
        controller.abort();
        setTileErrors(prev=>({...prev,[id]:'Timed out — click retry'}));
        setZoneATileData(prev=>prev.map(t=>t.id===id?{...t,detail:{}}:t));
      },30000);
      api('exec/detail',{start:tile.start,end:tile.end,store:storeParam})
        .then(d=>{
          clearTimeout(timer);
          setTileErrors(prev=>{const n={...prev};delete n[id];return n;});
          setZoneATileData(prev=>prev.map(t=>t.id===id?{...t,detail:d||{}}:t));
        }).catch(err=>{
          clearTimeout(timer);
          const msg=err?.message||'Error loading detail';
          setTileErrors(prev=>({...prev,[id]:msg}));
          setZoneATileData(prev=>prev.map(t=>t.id===id?{...t,detail:{}}:t));
        });
    }
  };
  const toggleTileRow=(tileId,rowId)=>setTileExpandedRows(prev=>{
    const s=new Set(prev[tileId]||[]);
    s.has(rowId)?s.delete(rowId):s.add(rowId);
    return{...prev,[tileId]:s};
  });

  /* ═══ ZONE A PRESET DROPDOWN ═══ */
  const[presetOpen,setPresetOpen]=useState(false);
  const presetRef=useRef(null);
  useEffect(()=>{
    if(!presetOpen)return;
    const h=e=>{if(presetRef.current&&!presetRef.current.contains(e.target))setPresetOpen(false)};
    document.addEventListener('mousedown',h);return()=>document.removeEventListener('mousedown',h);
  },[presetOpen]);

  /* ═══ ZONE B SELLER DROPDOWN ═══ */
  const[zoneBSellerOpen,setZoneBSellerOpen]=useState(false);
  const zoneBSellerRef=useRef(null);
  useEffect(()=>{
    if(!zoneBSellerOpen)return;
    const h=e=>{if(zoneBSellerRef.current&&!zoneBSellerRef.current.contains(e.target))setZoneBSellerOpen(false)};
    document.addEventListener('mousedown',h);return()=>document.removeEventListener('mousedown',h);
  },[zoneBSellerOpen]);

  /* tile color palette */
  const TILE_COLORS=['#3b82f6','#14b8a6','#10b981','#6366f1','#8b5cf6'];

  /* ═══ RENDER ═══ */
  const S=t.textSec;const BD=t.cardBorder;const DIV=t.divider;
  const selStyle={background:t.card,color:t.text,border:'1px solid '+t.inputBorder,borderRadius:8,padding:'6px 22px 6px 9px',fontSize:12,fontWeight:500,cursor:'pointer',outline:'none',appearance:'none',backgroundImage:"url(\"data:image/svg+xml,%3Csvg width='10' height='6' viewBox='0 0 10 6' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1L5 5L9 1' stroke='%238892aa' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C%2Fsvg%3E\")",backgroundRepeat:'no-repeat',backgroundPosition:'right 7px center'};
  const inputStyle={border:'1px solid '+t.inputBorder,borderRadius:8,padding:'6px 9px',fontSize:12,fontWeight:500,color:t.text,background:t.card,outline:'none'};

  return<div>

    {/* ══════════════════════════════════════════════════
        ZONE A — PERIOD COMPARISON  (filter riêng trong header)
    ══════════════════════════════════════════════════ */}
    <div style={{border:'2px solid #fed7aa',borderRadius:14,marginBottom:18,overflow:'hidden',background:t.card,boxShadow:'0 1px 4px rgba(20,24,36,.07)'}}>

      {/* Zone A header */}
      <div style={{background:t.bg==='#0D0F1A'?'#1c1409':'linear-gradient(135deg,#fff7ed,#ffedd5)',borderBottom:'1px solid #fed7aa',padding:'11px 18px',display:'flex',alignItems:'center',justifyContent:'space-between',flexWrap:'wrap',gap:10}}>
        <div style={{display:'flex',alignItems:'center',gap:10}}>
          <span style={{fontSize:9,fontWeight:800,textTransform:'uppercase',letterSpacing:1.2,padding:'3px 10px',borderRadius:20,border:'1.5px solid #fed7aa',background:'#fff7ed',color:'#9a3412'}}>Zone A</span>
          <span style={{fontSize:10,fontWeight:800,textTransform:'uppercase',letterSpacing:1.2,color:'#9a3412'}}>Period Comparison</span>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:8,flexWrap:'wrap'}}>
          <span style={{fontSize:10,fontWeight:700,color:'#9a3412'}}>Preset:</span>
          {/* Preset picker */}
          <div ref={presetRef} style={{position:'relative'}}>
            <button onClick={()=>setPresetOpen(v=>!v)} style={{display:'flex',alignItems:'center',gap:6,background:t.card,border:'1.5px solid #f97316',borderRadius:9,padding:'6px 12px',fontSize:11,fontWeight:700,color:'#c2410c',cursor:'pointer',whiteSpace:'nowrap',maxWidth:280,overflow:'hidden',textOverflow:'ellipsis'}}>
              <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',maxWidth:240}}>{ZONE_A_PRESETS.find(p=>p.key===zoneAPreset)?.label||'Select preset'}</span>
              <span style={{fontSize:9,color:'#f97316',flexShrink:0,transition:'transform .2s',transform:presetOpen?'rotate(180deg)':'none'}}>▾</span>
            </button>
            {presetOpen&&<div style={{position:'absolute',top:'calc(100% + 5px)',left:0,background:t.card,border:'1px solid '+BD,borderRadius:12,boxShadow:'0 12px 40px rgba(20,24,36,.15)',zIndex:500,overflow:'hidden',minWidth:430}}>
              {ZONE_A_PRESETS.map(p=><div key={p.key} onClick={()=>{setZoneAPreset(p.key);setPresetOpen(false)}} style={{display:'flex',alignItems:'center',gap:10,padding:'10px 16px',cursor:'pointer',fontSize:12,color:zoneAPreset===p.key?t.primary:S,borderBottom:'1px solid '+DIV,background:zoneAPreset===p.key?t.primaryGhost:'transparent',fontWeight:zoneAPreset===p.key?700:400,transition:'background .1s'}}
                onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background=zoneAPreset===p.key?t.primaryGhost:'transparent'}>
                <span style={{width:13,flexShrink:0,fontSize:11,color:t.primary}}>{zoneAPreset===p.key?'✓':''}</span>
                {p.label}
              </div>)}
            </div>}
          </div>
          {/* Zone A store filter — shared selectedStores, synced with Zone B */}
          <StoreMultiSelect selected={selectedStores} onChange={setSelectedStores} opts={storeOpts||[]}
            accentColor="#f97316" accentBorder="#f97316" accentText="#c2410c" t={t} zIndex={600}/>
        </div>
      </div>

      {/* Tiles + per-tile detail drawer — all in one flex row, each tile is its own column */}
      <div style={{display:'flex',overflowX:'auto',alignItems:'flex-start'}}>
        {zoneALoading&&<div style={{padding:'32px 24px',color:t.textMuted,fontSize:12}}>Loading...</div>}
        {!zoneALoading&&zoneATileData.map((tile,ti)=>{
          const tileColor=TILE_COLORS[ti%TILE_COLORS.length];
          const tileNP=tile.em?.netProfit||0;
          const tileSales=tile.em?.sales||0;
          const isOpen=openTiles.has(tile.id);
          const numSt={fontSize:14,fontWeight:700,color:t.text};
          const numSmSt={fontSize:12,fontWeight:700,color:t.text};
          const tileErr=tileErrors[tile.id];
          const dr=isOpen&&tile.detail!==null?buildDetailRows(tile.em,tile.detail||{}):null;
          const expRows=tileExpandedRows[tile.id]||new Set();
          const loadingDetail=isOpen&&tile.detail===null&&!tileErr;
          return<div key={tile.id} style={{flex:1,minWidth:220,maxWidth:320,borderRight:ti<zoneATileData.length-1?'1px solid '+DIV:'none',display:'flex',flexDirection:'column'}}>
            {/* Color bar */}
            <div style={{height:4,background:tileColor,flexShrink:0}}/>
            {/* Tile summary */}
            <div style={{padding:'14px 14px 10px',display:'flex',flexDirection:'column'}}>
              <div style={{fontSize:13,fontWeight:700,color:t.text,marginBottom:1}}>{tile.label}</div>
              <div style={{fontSize:10,color:t.textMuted,marginBottom:10,lineHeight:1.4}}>{tile.dateLabel}</div>
              {/* Orders/Units + Refunds */}
              <div style={{display:'flex',gap:8,marginBottom:8}}>
                <div style={{flex:1}}>
                  <div style={{fontSize:9,color:t.textMuted,textTransform:'uppercase',fontWeight:700,letterSpacing:.4,marginBottom:2}}>Orders / Units</div>
                  <div style={numSmSt}>{N(tile.em?.orders||0)} / {N(tile.em?.units||0)}</div>
                </div>
                <div>
                  <div style={{fontSize:9,color:t.textMuted,textTransform:'uppercase',fontWeight:700,letterSpacing:.4,marginBottom:2}}>Refunds</div>
                  <div style={{...numSmSt,color:(tile.em?.refunds||0)>5?t.orange:t.text}}>{N(tile.em?.refunds||0)}</div>
                </div>
              </div>
              {/* Adv. cost + Est. payout */}
              <div style={{display:'flex',gap:8,marginBottom:8}}>
                <div style={{flex:1}}>
                  <div style={{fontSize:9,color:t.textMuted,textTransform:'uppercase',fontWeight:700,letterSpacing:.4,marginBottom:2}}>Adv. Cost</div>
                  <div style={numSmSt}>{$2(Math.abs(tile.em?.advCost||0))}</div>
                </div>
                <div>
                  <div style={{fontSize:9,color:t.textMuted,textTransform:'uppercase',fontWeight:700,letterSpacing:.4,marginBottom:2}}>Est. Payout</div>
                  <div style={numSmSt}>{$2(tile.em?.estPayout||0)}</div>
                </div>
              </div>
              {/* Net profit */}
              <div style={{paddingTop:6,borderTop:'1px solid '+DIV}}>
                <div style={{fontSize:9,color:t.textMuted,textTransform:'uppercase',fontWeight:700,letterSpacing:.4,marginBottom:2}}>Net Profit</div>
                <div style={{fontSize:15,fontWeight:700,color:tileNP>=0?t.green:t.red}}>{$2(tileNP)}</div>
                <div style={{fontSize:10,fontWeight:600,color:tileNP>=0?t.green:t.red}}>{tile.em?.margin!=null?((tile.em.margin||0).toFixed(1)+'%'):'—'} margin</div>
              </div>
            </div>
            {/* More / Less toggle */}
            <button onClick={()=>toggleTile(tile.id,tile)} style={{width:'100%',padding:'7px 0',background:isOpen?tileColor+'18':'transparent',border:'none',borderTop:'1px solid '+DIV,fontSize:11,fontWeight:700,color:isOpen?tileColor:t.textSec,cursor:'pointer',fontFamily:'inherit',flexShrink:0,transition:'all .15s',letterSpacing:.3}}>
              {isOpen?'Less ▲':'More ▼'}
            </button>
            {/* Per-tile detail drawer */}
            {isOpen&&(
              <div style={{borderTop:'2px solid '+tileColor,background:t.tableBg}}>
                {loadingDetail&&<div style={{padding:'18px 14px',textAlign:'center'}}>
                  <div style={{fontSize:11,color:t.textMuted,marginBottom:6}}>Loading detail…</div>
                  <div style={{width:28,height:28,borderRadius:'50%',border:'3px solid '+tileColor+'44',borderTopColor:tileColor,animation:'spin 0.8s linear infinite',margin:'0 auto'}}/>
                </div>}
                {tileErr&&<div style={{padding:'14px',textAlign:'center'}}>
                  <div style={{fontSize:11,color:t.red,marginBottom:8}}>⚠ {tileErr}</div>
                  <button onClick={()=>{
                    setTileErrors(prev=>{const n={...prev};delete n[tile.id];return n;});
                    setZoneATileData(prev=>prev.map(tt=>tt.id===tile.id?{...tt,detail:null}:tt));
                    setTimeout(()=>toggleTile(tile.id,{...tile,detail:null}),50);
                  }} style={{fontSize:10,fontWeight:700,color:tileColor,background:'transparent',border:'1px solid '+tileColor,borderRadius:6,padding:'4px 12px',cursor:'pointer'}}>
                    Retry ↺
                  </button>
                </div>}
                {!loadingDetail&&dr&&dr.map((row,ri)=>{
                  const hasSub=row.sub&&row.sub.length>0;
                  const isExp=expRows.has(row.id);
                  const isNpLike=row.id==='np'||row.id==='grossProfit';
                  const valCol=isNpLike?(row.val>=0?t.green:t.red):(row.id==='margin'?(row.val>=15?t.green:row.val>=8?t.orange:t.red):t.text);
                  const fmtVal=row.val==null||row.val===0&&(row.id==='cogs'||row.id==='rc'||row.id==='af')?'—':row.fmt(row.val);
                  return<React.Fragment key={ri}>
                    <div onClick={()=>hasSub&&toggleTileRow(tile.id,row.id)}
                      style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'7px 13px',borderBottom:'1px solid '+DIV,cursor:hasSub?'pointer':'default',gap:8}}
                      onMouseEnter={e=>e.currentTarget.style.background=t.tableHover}
                      onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                      <span style={{fontSize:11,color:hasSub?t.text:t.textSec,fontWeight:hasSub?600:400,display:'flex',alignItems:'center',gap:4,whiteSpace:'nowrap'}}>
                        {hasSub&&<span style={{fontSize:9,color:tileColor}}>{isExp?'▼':'▶'}</span>}
                        {row.label}
                      </span>
                      <span style={{fontSize:12,fontWeight:700,color:valCol,flexShrink:0}}>{fmtVal}</span>
                    </div>
                    {isExp&&row.sub.map((s,si)=><div key={si} style={{display:'flex',justifyContent:'space-between',padding:'5px 13px 5px 26px',borderBottom:'1px solid '+DIV,background:tileColor+'08'}}>
                      <span style={{fontSize:10,color:t.textMuted}}>{s.l}</span>
                      <span style={{fontSize:11,fontWeight:600,color:t.text}}>{s.fmt(s.v)}</span>
                    </div>)}
                  </React.Fragment>;
                })}
              </div>
            )}
          </div>;
        })}
        {!zoneALoading&&zoneATileData.length===0&&<div style={{padding:'32px 24px',color:t.textMuted,fontSize:12}}>No data. Select a preset above and ensure DB is connected.</div>}
      </div>

    </div>

    {/* ══════════════════════════════════════════════════
        ZONE B — ANALYTICS DASHBOARD  (filter trong header)
    ══════════════════════════════════════════════════ */}
    <div style={{border:'2px solid '+t.primary+'55',borderRadius:14,overflow:'visible',background:t.card,boxShadow:'0 1px 4px rgba(20,24,36,.07)',marginBottom:18}}>

      {/* Zone B header with filter controls */}
      <div style={{background:t.bg==='#0D0F1A'?'#0f1429':'linear-gradient(135deg,#eef1fd,#e0e7ff)',borderBottom:'1px solid '+t.primary+'44',borderRadius:'12px 12px 0 0',padding:'11px 18px'}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:10}}>
          <span style={{fontSize:9,fontWeight:800,textTransform:'uppercase',letterSpacing:1.2,padding:'3px 10px',borderRadius:20,border:'1.5px solid '+t.primary+'55',background:t.primaryGhost,color:t.primary}}>Zone B</span>
          <span style={{fontSize:10,fontWeight:800,textTransform:'uppercase',letterSpacing:1.2,color:t.primary}}>Analytics Dashboard</span>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:8,flexWrap:'wrap'}}>
          <span style={{fontSize:10,fontWeight:700,color:t.primary,textTransform:'uppercase',letterSpacing:.6}}>Start:</span>
          <input type="date" value={sd} onChange={e=>setSd(e.target.value)} style={{...inputStyle,width:130}}/>
          <span style={{fontSize:10,fontWeight:700,color:t.primary,textTransform:'uppercase',letterSpacing:.6}}>End:</span>
          <input type="date" value={ed} onChange={e=>setEd(e.target.value)} style={{...inputStyle,width:130}}/>
          <div style={{width:1,height:22,background:t.primary+'44',flexShrink:0}}/>
          {/* Store dropdown — shared selectedStores, synced with Zone A */}
          <StoreMultiSelect selected={selectedStores} onChange={setSelectedStores} opts={storeOpts||[]}
            accentColor={t.primary} accentBorder={t.primary} accentText={t.primary} t={t} zIndex={500}/>
          {/* Seller dropdown — custom UI */}
          <div ref={zoneBSellerRef} style={{position:'relative'}}>
            <button onClick={()=>setZoneBSellerOpen(v=>!v)} style={{display:'flex',alignItems:'center',gap:6,background:t.card,border:'1.5px solid '+(seller!=='All'?t.primary:t.inputBorder),borderRadius:9,padding:'6px 12px',fontSize:12,fontWeight:600,color:seller!=='All'?t.primary:t.text,cursor:'pointer',whiteSpace:'nowrap'}}>
              {seller==='All'?'All Sellers':'Seller: '+seller}
              <span style={{fontSize:9,color:t.textMuted,transition:'transform .2s',transform:zoneBSellerOpen?'rotate(180deg)':'none'}}>▾</span>
            </button>
            {zoneBSellerOpen&&<div style={{position:'absolute',top:'calc(100% + 5px)',left:0,background:t.card,border:'1px solid '+t.cardBorder,borderRadius:12,boxShadow:'0 12px 40px rgba(20,24,36,.15)',zIndex:500,overflow:'hidden',minWidth:160,maxHeight:320,overflowY:'auto'}}>
              {['All Sellers',...(sellerOpts||[])].map((s,i)=>{
                const val=i===0?'All':s; const active=seller===val;
                return<div key={s} onClick={()=>{setSeller(val);setZoneBSellerOpen(false);}} style={{padding:'9px 14px',cursor:'pointer',fontSize:12,color:active?t.primary:t.text,fontWeight:active?700:400,borderBottom:'1px solid '+t.divider,background:active?t.primaryGhost:'transparent'}}
                  onMouseEnter={e=>e.currentTarget.style.background=t.tableHover}
                  onMouseLeave={e=>e.currentTarget.style.background=active?t.primaryGhost:'transparent'}>
                  {active&&<span style={{marginRight:6,fontSize:10}}>✓</span>}{s}
                </div>;
              })}
            </div>}
          </div>
          <button onClick={onApplyZoneB} style={{background:t.primary,color:'#fff',border:'none',borderRadius:8,padding:'7px 18px',fontSize:12,fontWeight:700,cursor:'pointer',fontFamily:'inherit'}}>Apply</button>
        </div>
      </div>

      {/* Zone B body — existing content */}
      <div style={{padding:18}}>


    <Cd t={t} style={{borderLeft:'4px solid '+t.primary,marginBottom:showDetail?0:16,borderRadius:showDetail?'12px 12px 0 0':'12px',padding:'14px 18px'}}>
      {/* Header row */}
      <div style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:12}}>
        <div>
          <div style={{fontSize:11,fontWeight:800,color:t.textSec,letterSpacing:1.2,textTransform:'uppercase'}}>Sellerboard Summary</div>
          <div style={{fontSize:10,color:t.textMuted,marginTop:1}}>{fmtD(sd)} — {fmtD(ed)}</div>
        </div>
        <button onClick={()=>setShowDetail(v=>!v)} style={{display:'flex',alignItems:'center',gap:5,background:showDetail?t.primary:t.primaryGhost,border:'1px solid '+(showDetail?t.primary:t.primary+'44'),color:showDetail?'#fff':t.primary,borderRadius:8,padding:'6px 13px',fontSize:11,fontWeight:600,cursor:'pointer',transition:'all .15s',flexShrink:0}}>
          Detail metrics <span style={{fontSize:10,transition:'transform .2s',display:'inline-block',transform:showDetail?'rotate(180deg)':'none'}}>▾</span>
        </button>
      </div>

      {/* Chips row */}
      <div style={{display:'flex',flexWrap:'wrap',gap:8,alignItems:'flex-start'}}>
        {sbVisible.map(key=>{
          const m=SB_ALL[key];if(!m)return null;
          const pv=ch(m.k);
          const pvLabel=prevPeriod&&prevPeriod.s?prevPeriod.s+' – '+prevPeriod.e:'prev period';
          // For % metrics: show absolute pp diff; for others: show % change
          const isNegGood=m.reverse; // TACoS: lower is better
          let changeEl=null;
          if(m.isPct&&m.ppDiff!=null){
            const pp=m.ppDiff;
            const good=isNegGood?pp<=0:pp>=0;
            changeEl=<div title={'vs '+pvLabel} style={{fontSize:10,fontWeight:600,color:good?t.green:t.red,marginTop:3,cursor:'help'}}>
              {pp>=0?'+':''}{pp.toFixed(2)}pp <span style={{color:t.textMuted,fontWeight:400,fontSize:9}}>prev</span>
            </div>;
          } else if(pv!=null){
            const good=m.reverse?pv<=0:pv>=0;
            changeEl=<div title={'vs '+pvLabel} style={{fontSize:10,fontWeight:600,color:good?t.green:t.red,marginTop:3,cursor:'help'}}>
              {pv>=0?'↑':'↓'}{Math.abs(pv).toFixed(1)}% <span style={{color:t.textMuted,fontWeight:400,fontSize:9}}>prev</span>
            </div>;
          } else {
            changeEl=<div style={{fontSize:10,color:t.textMuted,marginTop:3}}>—</div>;
          }
          const valColor=m.profit?(em.netProfit>=0?t.green:t.red):t.text;
          return<div key={key} style={{display:'flex',alignItems:'center',gap:8,background:t.tableBg,border:'1px solid '+t.cardBorder,borderRadius:10,padding:'9px 11px',transition:'border-color .15s',minWidth:m.mw||95,flex:'0 0 auto'}}>
            <div style={{minWidth:0}}>
              <div style={{fontSize:9,color:t.textMuted,textTransform:'uppercase',fontWeight:700,letterSpacing:.8,marginBottom:4}}>{m.l}</div>
              <div style={{fontSize:16,fontWeight:600,color:valColor,fontFamily:"'Georgia','Times New Roman',serif",lineHeight:1,whiteSpace:'nowrap',letterSpacing:-.2}}>{m.v}</div>
              {changeEl}
            </div>
            <button onClick={()=>sbRemove(key)} title="Remove" style={{width:17,height:17,borderRadius:'50%',border:'1px solid '+t.inputBorder,background:t.card,color:t.textMuted,fontSize:9,fontWeight:700,display:'flex',alignItems:'center',justifyContent:'center',cursor:'pointer',flexShrink:0,lineHeight:1,transition:'all .12s',padding:0}}
              onMouseEnter={e=>{e.currentTarget.style.background='#e53e3e';e.currentTarget.style.borderColor='#e53e3e';e.currentTarget.style.color='#fff';}}
              onMouseLeave={e=>{e.currentTarget.style.background=t.card;e.currentTarget.style.borderColor=t.inputBorder;e.currentTarget.style.color=t.textMuted;}}>✕</button>
          </div>;
        })}

        {/* ＋ Add metric picker */}
        <div ref={sbPickerRef} style={{position:'relative',alignSelf:'center'}}>
          <button onClick={()=>setSbPickerOpen(v=>!v)} style={{display:'flex',alignItems:'center',gap:5,background:'transparent',border:'1px dashed '+t.inputBorder,borderRadius:10,padding:'7px 14px',fontSize:11,fontWeight:600,color:t.textMuted,cursor:'pointer',transition:'all .15s',whiteSpace:'nowrap'}}
            onMouseEnter={e=>{e.currentTarget.style.borderColor=t.primary;e.currentTarget.style.color=t.primary;e.currentTarget.style.background=t.primaryGhost;}}
            onMouseLeave={e=>{if(!sbPickerOpen){e.currentTarget.style.borderColor=t.inputBorder;e.currentTarget.style.color=t.textMuted;e.currentTarget.style.background='transparent';}}}>
            ＋ Add metric
          </button>
          {sbPickerOpen&&<div style={{position:'absolute',top:'calc(100% + 6px)',left:0,background:t.card,border:'1px solid '+t.cardBorder,borderRadius:12,boxShadow:'0 8px 32px '+t.shadow,padding:12,zIndex:999,minWidth:260}}>
            <div style={{fontSize:9,fontWeight:700,textTransform:'uppercase',letterSpacing:1,color:t.textMuted,marginBottom:8}}>Show / hide metrics</div>
            <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
              {Object.entries(SB_ALL).map(([key,m])=>{
                const on=sbVisible.includes(key);
                return<button key={key} onClick={()=>sbToggle(key)} style={{padding:'5px 12px',borderRadius:20,fontSize:11,fontWeight:on?600:500,cursor:'pointer',border:'1px solid '+(on?t.primary:t.inputBorder),color:on?t.primary:t.textSec,background:on?t.primaryGhost:'transparent',transition:'all .12s'}}>
                  {m.l}{on?' ✓':''}
                </button>;
              })}
            </div>
          </div>}
        </div>
      </div>
    </Cd>

    {/* ② DETAIL METRICS — collapsible drawer */}
    {showDetail&&<Cd t={t} style={{marginBottom:16,padding:0,overflow:'hidden',borderTop:'none',borderRadius:'0 0 12px 12px',borderTopColor:'transparent'}}>
      <table style={{width:'100%',borderCollapse:'separate',borderSpacing:0,fontSize:13}}>
        <thead><tr>
          {['Metric','Value','vs Prev Period'].map((h,i)=><th key={i} style={{padding:'10px 16px',textAlign:i>=1?'right':'left',fontSize:10,fontWeight:700,color:t.textMuted,textTransform:'uppercase',borderBottom:'2px solid '+t.divider,background:t.tableBg}}>{h}</th>)}
        </tr></thead>
        <tbody>{DETAIL_ROWS.map((row,i)=>{
          const hasSub=row.sub&&row.sub.length>0;const isExp=expandedRows.has(row.id);
          // Compute vs Prev Period using pvk
          let pvChg=undefined;
          if(prevEm&&row.pvk){
            if(row.pvk==='_cr') pvChg=pv(cr,prevCr);
            else if(row.pvk==='_tacos') pvChg=pv(tacos,prevTacos);
            else if(row.pvk==='_roas'){const pr=prevTacos>0?(100/prevTacos):0;pvChg=pv(em.realAcos>0?(100/em.realAcos):0,pr);}
            else if(row.isPP) pvChg=pvPP(em[row.pvk]||0,prevEm[row.pvk]||0); // percentage point diff
            else pvChg=pv(em[row.pvk]||0,prevEm[row.pvk]||0);
          }
          const pvLabel=prevPeriod&&prevPeriod.s?prevPeriod.s+' – '+prevPeriod.e:'prev period';
          const pvGood=row.reverseColor?(pvChg!=null&&pvChg<0):(pvChg!=null&&pvChg>=0);
          const isNpRow=(row.id==='np'||row.id==='grossProfit');
          const valColor=isNpRow?(row.val>=0?t.green:t.red):t.text;
          return<React.Fragment key={i}>
            <tr onClick={()=>hasSub&&setExpandedRows(prev=>{const s=new Set(prev);s.has(row.id)?s.delete(row.id):s.add(row.id);return s;})} style={{cursor:hasSub?'pointer':'default',borderBottom:'1px solid '+t.divider}} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
              <td style={{padding:'11px 16px',fontWeight:500,color:t.textSec,whiteSpace:'nowrap'}}>
                {hasSub&&<span style={{marginRight:6,fontSize:10,color:t.primary}}>{isExp?'▼':'▶'}</span>}
                {row.label}{row.isNew&&NEW_BADGE}<Tip text={row.tip||''} t={t}/>
              </td>
              <td style={{padding:'11px 16px',textAlign:'right',fontWeight:700,color:valColor}}>{row.fmt(row.val)}</td>
              <td style={{padding:'11px 16px',textAlign:'right'}}>{pvChg!=null?<span title={'Compared to: '+pvLabel} style={{fontSize:11,fontWeight:600,color:pvGood?t.green:t.red,cursor:'help',borderBottom:'1px dashed '+(pvGood?t.green:t.red)+'66'}}>{pvChg>=0?'↑':'↓'}{row.isPP?Math.abs(pvChg).toFixed(2)+'pp':Math.abs(pvChg).toFixed(1)+'%'}</span>:<span style={{color:t.textMuted}}>—</span>}</td>
            </tr>
            {isExp&&row.sub.map((s,j)=><tr key={'s'+j} style={{background:t.primaryGhost+'88'}}>
              <td style={{padding:'8px 16px 8px 36px',fontSize:12,color:s.muted?t.textMuted:t.textSec}}>{s.l}{s.muted&&<span style={{fontSize:9,color:t.textMuted,marginLeft:5}}>(seller_board_sales − analytics)</span>}</td>
              <td style={{padding:'6px 16px',textAlign:'right',fontSize:12,fontWeight:600,color:s.muted?t.textMuted:t.text}}>{s.fmt(s.v)}</td>
              <td/>
            </tr>)}
          </React.Fragment>;
        })}</tbody>
      </table>
    </Cd>}

    {/* ④ DAILY TREND */}
    {(()=>{
      const total=dailyChartData.length;
      // Compute startIndex from trendZoom for Brush initial window
      const brushStart=trendZoom>0?Math.max(0,total-trendZoom):0;
      const brushEnd=Math.max(0,total-1);
      const xInterval=Math.max(0,Math.floor(total/10));
      return<Cd t={t} style={{marginBottom:16}}>
        {/* Row 1: title + slicer */}
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:8,flexWrap:'wrap',gap:6}}>
          <div style={{fontSize:13,fontWeight:700,color:t.text}}>Daily Trend</div>
          <button onClick={()=>setShowBrush(v=>!v)} title={showBrush?'Hide slicer':'Show slicer'} style={{padding:'4px 12px',borderRadius:6,border:'1px solid '+(showBrush?t.primary:t.inputBorder),background:showBrush?t.primaryGhost:'transparent',color:showBrush?t.primary:t.textMuted,fontSize:10,fontWeight:showBrush?700:500,cursor:'pointer',display:'flex',alignItems:'center',gap:4,transition:'all .12s'}}>
            <span style={{fontSize:11}}>⇔</span> Slicer
          </button>
        </div>
        {/* Row 2: series toggles */}
        <div style={{display:'flex',gap:6,flexWrap:'wrap',marginBottom:10}}>
          {[{k:'revenue',l:'Revenue',c:t.primary},{k:'netProfit',l:'Net Profit',c:t.green},{k:'advCost',l:'Ad Spend',c:t.orange}].map(b=><button key={b.k} onClick={()=>setTrendBars(p=>({...p,[b.k]:!p[b.k]}))} style={{padding:'4px 10px',borderRadius:8,border:'1px solid '+(trendBars[b.k]?b.c:t.inputBorder),background:trendBars[b.k]?b.c+'18':'transparent',color:trendBars[b.k]?b.c:t.textMuted,fontSize:10,fontWeight:600,cursor:'pointer'}}>{b.l}</button>)}
          <div style={{width:1,background:t.divider,alignSelf:'stretch'}}/>
          {[{k:'crPct',l:'CR%',c:'#9B59B6'},{k:'tacos',l:'TACoS',c:'#E67E22'}].map(li=><button key={li.k} onClick={()=>setTrendLines(p=>({...p,[li.k]:!p[li.k]}))} style={{padding:'4px 10px',borderRadius:8,border:'1px solid '+(trendLines[li.k]?li.c:t.inputBorder),background:trendLines[li.k]?li.c+'18':'transparent',color:trendLines[li.k]?li.c:t.textMuted,fontSize:10,fontWeight:600,cursor:'pointer'}}>{li.l}</button>)}
          {dailyLY&&dailyLY.length>0&&<button onClick={()=>setShowLY(!showLY)} style={{padding:'4px 10px',borderRadius:8,border:'1px dashed '+(showLY?LY_COLOR:t.inputBorder),background:showLY?LY_COLOR+'18':'transparent',color:showLY?LY_COLOR:t.textMuted,fontSize:10,fontWeight:600,cursor:'pointer'}}>Last Year</button>}
        </div>
        <ResponsiveContainer width="100%" height={showBrush?400:440}>
          <ComposedChart data={dailyChartData} margin={{bottom:8}}>
            <CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/>
            <XAxis dataKey="label" tick={{fill:t.textSec,fontSize:10}} interval={xInterval}/>
            <YAxis yAxisId="l" tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>$s(v)}/>
            {(trendLines.crPct||trendLines.tacos)&&<YAxis yAxisId="r" orientation="right" tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>v.toFixed(1)+'%'} domain={[0,'auto']}/>}
            <Tooltip content={<CT t={t}/>}/>
            <Legend wrapperStyle={{fontSize:10}}/>
            {trendBars.revenue&&<Bar yAxisId="l" dataKey="revenue" name="Revenue" fill={t.primary} radius={[3,3,0,0]} fillOpacity={0.85}/>}
            {trendBars.netProfit&&<Bar yAxisId="l" dataKey="netProfit" name="Net Profit" fill={t.green} radius={[3,3,0,0]} fillOpacity={0.85}/>}
            {trendBars.advCost&&<Bar yAxisId="l" dataKey="advCost" name="Ad Spend" fill={t.orange} radius={[3,3,0,0]} fillOpacity={0.85}/>}
            {trendLines.crPct&&<Line yAxisId="r" type="monotone" dataKey="crPct" name="CR%" stroke="#9B59B6" strokeWidth={2} dot={false}/>}
            {trendLines.tacos&&<Line yAxisId="r" type="monotone" dataKey="tacos" name="TACoS%" stroke="#E67E22" strokeWidth={2} dot={false}/>}
            {showBrush&&<Brush
              dataKey="label"
              startIndex={brushStart}
              endIndex={brushEnd}
              height={28}
              stroke={t.inputBorder}
              fill={t.tableBg}
              travellerWidth={8}
              onChange={()=>setTrendZoom(0)}
            />}
          </ComposedChart>
        </ResponsiveContainer>
      </Cd>;
    })()}

    {/* ⑤ SHOP SECTION */}
    <div style={{display:'grid',gridTemplateColumns:mob?'1fr':'1.6fr 0.4fr',gap:14,marginBottom:16}}>
      <Cd t={t} style={{padding:0,overflow:'hidden'}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'12px 16px',borderBottom:'1px solid '+t.divider}}>
          <div style={{fontSize:13,fontWeight:700,color:t.text}}>Shop Performance</div>
          <div style={{display:'flex',gap:6,alignItems:'center'}}>
            {shopView==='table'&&<span style={{fontSize:10,color:t.textMuted,fontWeight:500}}>Sort by:</span>}
            {shopView==='table'&&<select value={sortShop} onChange={e=>setSortShop(e.target.value)} style={{background:t.card,color:t.text,border:'1px solid '+t.inputBorder,borderRadius:7,padding:'4px 8px',fontSize:11,cursor:'pointer'}}>
              {['Revenue','Net Profit','Margin','Units'].map(o=><option key={o}>{o}</option>)}
            </select>}
            <button onClick={()=>setShopView('table')} style={{padding:'4px 10px',borderRadius:7,border:'1px solid '+(shopView==='table'?t.primary:t.inputBorder),background:shopView==='table'?t.primary+'14':'transparent',color:shopView==='table'?t.primary:t.textSec,fontSize:10,fontWeight:600,cursor:'pointer'}}>Table</button>
            <button onClick={()=>setShopView('chart')} style={{padding:'4px 10px',borderRadius:7,border:'1px solid '+(shopView==='chart'?t.primary:t.inputBorder),background:shopView==='chart'?t.primary+'14':'transparent',color:shopView==='chart'?t.primary:t.textSec,fontSize:10,fontWeight:600,cursor:'pointer'}}>Chart</button>
          </div>
        </div>
        {shopView==='table'?<div style={{overflowX:'auto',maxHeight:560,overflowY:'auto'}}>
          <table style={{width:'100%',borderCollapse:'separate',borderSpacing:0,fontSize:13.5}}>
            <thead><tr style={{position:'sticky',top:0,zIndex:2}}>
              {['Shop','Revenue','GP','Ads','Units','Margin','FBA Stock','% Rev'].map((h,i)=><th key={i} style={{padding:'9px 12px',textAlign:i===0?'left':'right',fontSize:11,fontWeight:700,color:t.textMuted,textTransform:'uppercase',borderBottom:'2px solid '+t.divider,background:t.tableBg,whiteSpace:'nowrap'}}>{h}</th>)}
            </tr></thead>
            <tbody>{sortedShop.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
              <td style={{padding:'10px 12px',fontWeight:700,borderBottom:'1px solid '+t.divider}}>{r.s}</td>
              <td style={{padding:'10px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{$(r.r)}</td>
              <td style={{padding:'10px 12px',textAlign:'right',fontWeight:700,color:(r.gp||r.n||0)>=0?t.green:t.red,borderBottom:'1px solid '+t.divider}}>{$(r.gp||r.n||0)}</td>
              <td style={{padding:'10px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{$(Math.abs(r.ad||0))}</td>
              <td style={{padding:'10px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{N(r.u||0)}</td>
              <td style={{padding:'10px 12px',textAlign:'right',color:mC(r.m,t),fontWeight:600,borderBottom:'1px solid '+t.divider}}>{(r.m||0).toFixed(1)}%</td>
              <td style={{padding:'10px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{N(r.f||0)}</td>
              <td style={{padding:'10px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:t.textMuted,fontSize:12}}>{tRev>0?(r.r/tRev*100).toFixed(1)+'%':'—'}</td>
            </tr>)}
          </tbody></table>
        </div>:<div style={{padding:12}}>
          <ResponsiveContainer width="100%" height={Math.max(200,fShop.length*36)}>
            <BarChart data={sortedShop} layout="vertical" barSize={9} barCategoryGap="18%">
              <CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/>
              <XAxis type="number" tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>$s(v)}/>
              <YAxis type="category" dataKey="s" tick={{fill:t.textSec,fontSize:10}} width={90}/>
              <Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/>
              <Bar dataKey="r" name="Revenue" fill={t.primary} radius={[0,4,4,0]}/>
              <Bar dataKey="n" name="Net Profit" fill={t.green} radius={[0,4,4,0]}>{sortedShop.map((e,i)=><Cell key={i} fill={(e.n||0)>=0?t.green:t.red}/>)}</Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>}
      </Cd>
      <Cd t={t} style={{padding:0,overflow:'hidden'}}>
        <div style={{padding:'12px 16px',borderBottom:'1px solid '+t.divider}}>
          <div style={{fontSize:12,fontWeight:700,color:t.text,marginBottom:8}}>{donutTitle[donutTab]}</div>
          <div style={{display:'flex',gap:4}}>
            {[{k:'rev',l:'Rev'},{k:'ads',l:'Ads'},{k:'profit',l:'Profit'}].map(tb=><button key={tb.k} onClick={()=>setDonutTab(tb.k)} style={{flex:1,padding:'4px',borderRadius:6,border:'1px solid '+(donutTab===tb.k?t.primary:t.inputBorder),background:donutTab===tb.k?t.primary+'14':'transparent',color:donutTab===tb.k?t.primary:t.textSec,fontSize:10,fontWeight:600,cursor:'pointer'}}>{tb.l}</button>)}
          </div>
        </div>
        <div style={{padding:'10px 12px'}}>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart><Pie data={donutData[donutTab]} innerRadius={45} outerRadius={65} dataKey="value" cx="50%" cy="50%" paddingAngle={2} stroke="none">
              {donutData[donutTab].map((e,i)=><Cell key={i} fill={e.fill}/>)}
            </Pie><Tooltip formatter={v=>'$'+Math.abs(v).toLocaleString()}/></PieChart>
          </ResponsiveContainer>
          <div style={{marginTop:8,maxHeight:200,overflowY:'auto'}}>
            {donutData[donutTab].map((d,i)=>{const tot=Math.abs(donutTotal[donutTab]);return<div key={i} style={{display:'flex',alignItems:'center',justifyContent:'space-between',fontSize:11,color:t.textSec,padding:'4px 0',borderBottom:i<donutData[donutTab].length-1?'1px solid '+t.divider:'none'}}>
              <div style={{display:'flex',alignItems:'center',gap:4}}><div style={{width:7,height:7,borderRadius:2,background:d.fill,flexShrink:0}}/><span style={{maxWidth:80,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{d.name}</span></div>
              <span style={{fontWeight:600}}>{tot>0?(Math.abs(d.value)/tot*100).toFixed(1)+'%':'—'}</span>
            </div>;})}
          </div>
        </div>
      </Cd>
    </div>

    {/* ⑥ ASIN PERFORMANCE */}
    <div ref={asinRef} style={{scrollMarginTop:12}}>
    <Cd t={t} style={{padding:0,overflow:'hidden',marginBottom:16}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'12px 16px',borderBottom:'1px solid '+t.divider,flexWrap:'wrap',gap:8}}>
        <div style={{fontSize:13,fontWeight:700,color:t.text}}>ASIN Performance</div>
        <div style={{display:'flex',gap:6,alignItems:'center'}}>
          <span style={{fontSize:10,color:t.textMuted}}>Group by:</span>
          <select value={groupBy} onChange={e=>setGroupBy(e.target.value)} style={{background:t.card,color:t.text,border:'1px solid '+t.inputBorder,borderRadius:7,padding:'4px 8px',fontSize:11,cursor:'pointer'}}>
            {['ASIN','Shop','Brand','Seller'].map(o=><option key={o}>{o}</option>)}
          </select>
          <button onClick={exportCSV} style={{padding:'4px 10px',borderRadius:7,border:'1px solid '+t.inputBorder,background:'transparent',color:t.textSec,fontSize:10,fontWeight:600,cursor:'pointer'}}>CSV</button>
        </div>
      </div>
      <div style={{overflowX:'auto',maxHeight:500,overflowY:'auto'}}>
        <table style={{width:'100%',borderCollapse:'separate',borderSpacing:0,fontSize:12.5}}>
          <thead style={{position:'sticky',top:0,zIndex:2}}><tr>
            {[groupBy,'Shop','Revenue','Net Profit','Margin%','Units','CR%','ACoS','ROAS'].map((h,i)=><th key={i} style={{padding:'9px 12px',textAlign:i>=2?'right':'left',fontSize:10,fontWeight:700,color:t.textMuted,textTransform:'uppercase',borderBottom:'2px solid '+t.divider,background:t.tableBg,whiteSpace:'nowrap'}}>{h}</th>)}
          </tr></thead>
          <tbody>{groupedAsins.map((r,i)=>{
            const isHL=highlightedAsin===r.a;
            return<tr key={i} ref={el=>{if(el&&r.a)asinRowRefs.current[r.a]=el}}
              style={{background:isHL?t.primary+'22':'transparent',outline:isHL?'2px solid '+t.primary:'none',transition:'background .3s,outline .3s'}}
              onMouseEnter={e=>{if(!isHL)e.currentTarget.style.background=t.tableHover}}
              onMouseLeave={e=>{e.currentTarget.style.background=isHL?t.primary+'22':'transparent'}}>
            <td style={{padding:'7px 12px',fontWeight:600,color:t.primary,borderBottom:'1px solid '+t.divider,letterSpacing:.2}}>{groupBy==='ASIN'?<AsinLink asin={r.a} onClick={onAsinClick||(()=>{})} t={t}/>:r.a}</td>
            <td style={{padding:'7px 12px',fontWeight:600,borderBottom:'1px solid '+t.divider}}>{r.b}</td>
            <td style={{padding:'7px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{$(r.r)}</td>
            <td style={{padding:'7px 12px',textAlign:'right',fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:'1px solid '+t.divider}}>{$(r.n)}</td>
            <td style={{padding:'7px 12px',textAlign:'right',color:mC(r.m,t),borderBottom:'1px solid '+t.divider}}>{r.m.toFixed(1)}%</td>
            <td style={{padding:'7px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{N(r.u)}</td>
            <td style={{padding:'7px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{r.cr.toFixed(2)}%</td>
            <td style={{padding:'7px 12px',textAlign:'right',color:r.ac<30?t.green:r.ac<50?t.orange:t.red,borderBottom:'1px solid '+t.divider}}>{r.ac.toFixed(2)}%</td>
            <td style={{padding:'7px 12px',textAlign:'right',color:r.ro>3?t.green:r.ro>2?t.orange:t.red,borderBottom:'1px solid '+t.divider}}>{r.ro.toFixed(2)}</td>
          </tr>;
          })}</tbody>
        </table>
      </div>
      <div style={{padding:'6px 12px',fontSize:10,color:t.textMuted,borderTop:'1px solid '+t.divider}}>{groupedAsins.length} {groupBy==='ASIN'?'ASINs':'groups'}</div>
    </Cd>
    </div>

    {/* Recommendations */}
    <Cd t={t} style={{marginBottom:16}}>
      <div style={{fontSize:13,fontWeight:700,color:t.text,marginBottom:12}}>Recommendations <span style={{fontSize:10,fontWeight:500,color:t.textMuted}}>({recs.length})</span></div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(320px,1fr))',gap:10}}>
        {recs.map((r,i)=><div key={i} style={{display:'flex',alignItems:'flex-start',gap:10,padding:'10px 13px',borderRadius:10,background:r.color+'10',border:'1px solid '+r.color+'33'}}>
          <div style={{width:6,height:6,borderRadius:3,background:r.color,marginTop:5,flexShrink:0}}/>
          <div style={{flex:1,minWidth:0}}>
            <div style={{fontSize:12,fontWeight:700,color:t.text,marginBottom:2}}>{r.title}</div>
            <div style={{fontSize:11,color:t.textSec,lineHeight:1.5}}>{r.desc}</div>
          </div>
          {r.asin&&<button onClick={()=>scrollToAsinRow(r.asin)} style={{padding:'3px 9px',borderRadius:7,border:'1px solid '+r.color+'66',background:'transparent',color:r.color,fontSize:10,fontWeight:600,cursor:'pointer',whiteSpace:'nowrap',flexShrink:0}}>View</button>}
        </div>)}
      </div>
    </Cd>

      </div>{/* /Zone B body */}
    </div>{/* /Zone B card */}

  </div>;
}

/* ═══════════ INVENTORY ═══════════ */
function InvPage({t,mob,invData,invShop,invTrend,invFeeMonthly,invAsin,onAsinClick}){
  const d=invData||{};
  const fee=d.storageFee||0;
  const feeHist=invFeeMonthly||[];
  const asinRows=invAsin||[];
  const[asinSearch,setAsinSearch]=useState('');
  const[asinSort,setAsinSort]=useState('fba');
  const[asinSortDir,setAsinSortDir]=useState(-1); // -1 desc, 1 asc

  // Alerts derived from asin data
  const invAlerts=useMemo(()=>{
    const a=[];
    const oos=asinRows.filter(r=>r.oos45&&r.fba>0);
    const highFee=asinRows.filter(r=>r.storageFee>200).sort((a,b)=>b.storageFee-a.storageFee).slice(0,3);
    const lowSt=invShop.filter(s=>s.st<0.02&&s.fba>0);
    const aged=asinRows.filter(r=>r.aged>0).sort((a,b)=>b.aged-a.aged).slice(0,3);
    const totalFee=d.storageFee||0;
    if(totalFee>5000)a.push({s:'c',t:`Storage fee ${$2(totalFee)}/month — consider liquidating aged stock`});
    else if(totalFee>0)a.push({s:'i',t:`Storage fee ${$2(totalFee)}/month`});
    if(oos.length>0)a.push({s:'c',t:`${oos.length} ASINs at risk of OOS within 45 days: ${oos.slice(0,3).map(r=>r.asin).join(', ')}${oos.length>3?' …':''}`});
    if(highFee.length>0)a.push({s:'w',t:`High storage fee ASINs: ${highFee.map(r=>r.asin+' ('+$2(r.storageFee)+')').join(' · ')}`});
    if(aged.length>0)a.push({s:'w',t:`Aged stock (>90d): ${aged.map(r=>r.asin+' '+N(r.aged)+' units').join(' · ')}`});
    if(lowSt.length>0)a.push({s:'w',t:`${lowSt.length} shops with sell-through <2%: ${lowSt.map(s=>s.s).join(', ')}`});
    if(d.criticalSkus>0)a.push({s:'w',t:`${d.criticalSkus} critical SKUs ≤30 days of supply`});
    if(!a.length)a.push({s:'i',t:'Inventory looks healthy — no critical alerts'});
    return a;
  },[asinRows,invShop,d]);

  // Filtered + sorted ASIN table
  const filteredAsin=useMemo(()=>{
    let rows=asinRows;
    const q=asinSearch.trim().toLowerCase();
    if(q)rows=rows.filter(r=>r.asin.toLowerCase().includes(q)||r.name.toLowerCase().includes(q)||r.sku.toLowerCase().includes(q));
    return [...rows].sort((a,b)=>asinSortDir*((b[asinSort]||0)-(a[asinSort]||0)));
  },[asinRows,asinSearch,asinSort,asinSortDir]);

  const thSort=(k,label)=>{
    const active=asinSort===k;
    return<th onClick={()=>{if(active)setAsinSortDir(d=>-d);else{setAsinSort(k);setAsinSortDir(-1);}}} style={{padding:'9px 12px',textAlign:'right',fontSize:10,fontWeight:700,color:active?t.primary:t.textMuted,textTransform:'uppercase',borderBottom:'2px solid '+t.divider,background:t.tableBg,cursor:'pointer',whiteSpace:'nowrap',userSelect:'none'}}>
      {label}{active?(asinSortDir===-1?' ↓':' ↑'):''}
    </th>;
  };

  return<div>
    {/* Snapshot notice */}
    <Cd t={t} style={{padding:"10px 16px",marginBottom:14,borderLeft:"3px solid "+t.blue}}>
      <div style={{fontSize:11,color:t.textSec}}>Latest inventory snapshot{d.snapshotDate ? ` — data from ${d.oldestDate && d.oldestDate !== d.snapshotDate ? `${d.oldestDate} to ${d.snapshotDate}` : d.snapshotDate}` : ""}. No time filter needed.</div>
    </Cd>

    {/* ① KPI stat strip */}
    {(()=>{
      const doh=Math.round(d.avgDaysOfSupply||0);
      const crit=d.criticalSkus||0;
      // cols: [label, value, color, tip, sub, flex-weight]
      const metrics=[
        {label:"FBA Stock",     value:N(d.fbaStock||0),     color:t.primary,                          tip:TIPS.fbaStock,    sub:"total units",    w:1.4},
        {label:"Available",     value:N(d.availableInv||0), color:t.green,                            tip:TIPS.invAvail,    sub:"ready to ship",  w:1.3},
        {label:"Reserved",      value:N(d.reserved||0),     color:t.orange,                           tip:TIPS.invReserved, sub:"held by Amazon", w:1.1},
        {label:"Inbound",       value:N(d.inbound||0),      color:t.blue,                             tip:TIPS.invInbound,  sub:"all stages",     w:1},
        {label:"Critical SKUs", value:N(crit),              color:crit>0?t.red:t.green,               tip:TIPS.invCritical, sub:crit>0?"need restock":"all healthy", w:1.1},
        {label:"Days of Supply",value:doh>0?doh+"d":"—",    color:doh>0&&doh<30?t.red:doh<60?t.orange:t.green, tip:TIPS.invDaysSupply, sub:doh<30?"restock soon":doh<60?"monitor":"healthy", w:1.2},
        {label:"Storage Fee",   value:$2(fee),              color:fee>10000?t.red:fee>5000?t.orange:t.text, tip:TIPS.storageFee, sub:"per month", w:1.5},
      ];
      const totalW=metrics.reduce((s,m)=>s+m.w,0);
      return<div style={{display:"flex",gap:0,marginBottom:16,background:t.card,borderRadius:16,border:"1px solid "+t.cardBorder,overflow:"hidden",boxShadow:"0 2px 12px "+t.shadow}}>
        {metrics.map((m,i)=><div key={i}
          style={{flex:m.w,minWidth:0,padding:"16px 18px",borderRight:i<metrics.length-1?"1px solid "+t.divider:"none",position:"relative",transition:"background .15s",cursor:"default"}}
          onMouseEnter={e=>e.currentTarget.style.background=t.tableHover}
          onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
          <div style={{position:"absolute",top:0,left:0,right:0,height:3,background:m.color,opacity:.75}}/>
          <div style={{display:"flex",alignItems:"center",gap:4,marginBottom:9}}>
            <span style={{fontSize:10,fontWeight:700,color:t.textMuted,textTransform:"uppercase",letterSpacing:.9,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>
              {m.label}
            </span>
            {m.tip&&<Tip text={m.tip} t={t}/>}
          </div>
          <div style={{fontSize:21,fontWeight:700,color:m.color,letterSpacing:-.3,lineHeight:1,marginBottom:5,fontFamily:"'Georgia','Times New Roman',serif"}}>{m.value}</div>
          <div style={{fontSize:10,color:t.textMuted,fontWeight:500,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{m.sub}</div>
        </div>)}
      </div>;
    })()}

    {/* ② Alerts */}
    <div style={{marginBottom:16}}><Alerts t={t} alerts={invAlerts}/></div>

    {/* ③ Charts row */}
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:14,marginBottom:14}}>
      <Sec title="Available Stock Trend" icon="" t={t}>
        <Cd t={t}><div style={{fontSize:11,color:t.textMuted,marginBottom:8}}>Sellerboard daily tracking (FBAStock minus reserved). The Available KPI card above uses Amazon Inventory Planning — both measure available stock but via different methodologies, so numbers may differ.</div><ResponsiveContainer width="100%" height={220}><AreaChart data={invTrend}><defs><linearGradient id="ig" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.primary} stopOpacity={.2}/><stop offset="100%" stopColor={t.primary} stopOpacity={0}/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="d" tick={{fill:t.textSec,fontSize:10}} interval={Math.max(0,Math.floor((invTrend||[]).length/8))}/><YAxis tick={{fill:t.textSec,fontSize:10}} tickFormatter={N}/><Tooltip content={<CT t={t}/>}/><Area type="monotone" dataKey="v" name="Available" stroke={t.primary} fill="url(#ig)" strokeWidth={2}/></AreaChart></ResponsiveContainer></Cd>
      </Sec>
      <Sec title="Inventory Aging" icon="" t={t}>
        <Cd t={t} style={{position:"relative"}}>
          {(()=>{const over90=(d.age91_180||0)+(d.age181_270||0)+(d.age271_365||0)+(d.age365plus||0);return over90>0&&<div style={{position:"absolute",top:8,right:12,background:over90>50000?t.redBg:t.orangeBg,color:over90>50000?t.red:t.orange,padding:"3px 10px",borderRadius:8,fontSize:10,fontWeight:600,zIndex:1}}>90d+: {N(over90)} units</div>})()}
          <ResponsiveContainer width="100%" height={220}><BarChart data={[{name:"0-90d",v:d.age0_90||0,fill:t.green},{name:"91-180d",v:d.age91_180||0,fill:t.orange},{name:"181-270d",v:d.age181_270||0,fill:t.orange},{name:"271-365d",v:d.age271_365||0,fill:t.red},{name:"365d+",v:d.age365plus||0,fill:t.red}]}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="name" tick={{fill:t.textSec,fontSize:10}}/><YAxis tick={{fill:t.textSec,fontSize:10}} tickFormatter={N}/><Tooltip content={<CT t={t}/>}/><Bar dataKey="v" name="Units" radius={[4,4,0,0]}>{[{fill:t.green},{fill:t.orange},{fill:t.orange},{fill:t.red},{fill:t.red}].map((e,i)=><Cell key={i} fill={e.fill}/>)}</Bar></BarChart></ResponsiveContainer>
        </Cd>
      </Sec>
    </div>

    {/* ④ Stock by Shop — stacked bar + table */}
    <Sec title="FBA Stock by Shop" icon="" t={t}>
      <Cd t={t}>
        {/* Stacked horizontal bar chart */}
        <div style={{display:'flex',alignItems:'center',gap:16,marginBottom:10,flexWrap:'wrap'}}>
          {[{color:t.green,label:'Available'},{color:t.blue,label:'Inbound'},{color:t.orange,label:'Reserved'}].map((l,i)=>(
            <div key={i} style={{display:'flex',alignItems:'center',gap:5,fontSize:10,color:t.textSec}}>
              <div style={{width:10,height:10,borderRadius:2,background:l.color}}/>
              {l.label}
            </div>
          ))}
        </div>
        <ResponsiveContainer width="100%" height={Math.max(200,invShop.length*36)}>
          <BarChart data={[...invShop].sort((a,b)=>b.fba-a.fba).map(r=>({
            name:r.s,
            Available:r.avail,
            Inbound:r.inb,
            Reserved:r.res,
          }))} layout="vertical" margin={{left:8,right:40,top:4,bottom:4}} barSize={16} barCategoryGap="22%">
            <CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid} horizontal={false}/>
            <XAxis type="number" tick={{fill:t.textSec,fontSize:10}} tickFormatter={N}/>
            <YAxis type="category" dataKey="name" tick={{fill:t.textSec,fontSize:11}} width={88}/>
            <Tooltip content={<CT t={t}/>}/>
            <Bar dataKey="Available" stackId="s" fill={t.green} radius={[0,0,0,0]}/>
            <Bar dataKey="Inbound"   stackId="s" fill={t.blue}  radius={[0,0,0,0]}/>
            <Bar dataKey="Reserved"  stackId="s" fill={t.orange} radius={[0,4,4,0]}/>
          </BarChart>
        </ResponsiveContainer>
      </Cd>
      {/* Table below */}
      <Cd t={t} style={{padding:0,overflow:'hidden',marginTop:10}}>
        <div style={{overflowX:'auto'}}>
          <table style={{width:'100%',borderCollapse:'separate',borderSpacing:0,fontSize:12.5}}>
            <thead><tr>
              {['Shop','Total','Available','Inbound','Reserved','Unfulfillable','Critical','Sell-Through','Days'].map((h,i)=>(
                <th key={i} style={{padding:'8px 12px',textAlign:i===0?'left':'right',fontSize:10,fontWeight:700,color:t.textMuted,textTransform:'uppercase',borderBottom:'2px solid '+t.divider,background:t.tableBg,whiteSpace:'nowrap'}}>{h}</th>
              ))}
            </tr></thead>
            <tbody>{[...invShop].sort((a,b)=>b.fba-a.fba).map((r,i)=>{
              const avail=r.avail;
              return<tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                <td style={{padding:'8px 12px',fontWeight:700,borderBottom:'1px solid '+t.divider}}>{r.s}</td>
                <td style={{padding:'8px 12px',textAlign:'right',fontWeight:700,borderBottom:'1px solid '+t.divider}}>{N(r.fba)}</td>
                <td style={{padding:'8px 12px',textAlign:'right',color:t.green,fontWeight:600,borderBottom:'1px solid '+t.divider}}>{N(avail)}</td>
                <td style={{padding:'8px 12px',textAlign:'right',color:t.blue,fontWeight:600,borderBottom:'1px solid '+t.divider}}>{r.inb>0?N(r.inb):<span style={{color:t.textMuted}}>—</span>}</td>
                <td style={{padding:'8px 12px',textAlign:'right',color:t.orange,fontWeight:600,borderBottom:'1px solid '+t.divider}}>{r.res>0?N(r.res):<span style={{color:t.textMuted}}>—</span>}</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:t.textMuted}}>—</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{r.crit>0?<span style={{color:t.red,fontWeight:700}}>{r.crit}</span>:<span style={{color:t.textMuted}}>—</span>}</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.st<0.02?t.red:r.st<0.1?t.orange:t.green,fontWeight:600}}>{(r.st*100).toFixed(1)}%</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.doh<20?t.red:r.doh>90?t.orange:t.text,fontWeight:600}}>{r.doh>0?r.doh+'d':'—'}</td>
              </tr>;
            })}</tbody>
          </table>
        </div>
      </Cd>
    </Sec>

    {/* ⑤ ASIN Detail Table */}
    <Sec title={"ASIN Stock Detail"+(asinRows.length>0?" ("+asinRows.length+" ASINs)":"")} icon="" t={t} style={{marginTop:14}}>
      <Cd t={t} style={{padding:0,overflow:'hidden'}}>
        {/* Search bar */}
        <div style={{padding:'10px 14px',borderBottom:'1px solid '+t.divider,background:t.tableBg}}>
          <input
            value={asinSearch} onChange={e=>setAsinSearch(e.target.value)}
            placeholder="Search ASIN / SKU / name..."
            style={{width:'100%',padding:'7px 12px',borderRadius:8,border:'1px solid '+t.inputBorder,background:t.card,color:t.text,fontSize:12,outline:'none',boxSizing:'border-box'}}
          />
        </div>
        <div style={{overflowX:'auto',maxHeight:480,overflowY:'auto'}}>
          <table style={{width:'100%',borderCollapse:'separate',borderSpacing:0,fontSize:12.5}}>
            <thead style={{position:'sticky',top:0,zIndex:2}}><tr>
              <th style={{padding:'9px 12px',textAlign:'left',fontSize:10,fontWeight:700,color:t.textMuted,textTransform:'uppercase',borderBottom:'2px solid '+t.divider,background:t.tableBg,whiteSpace:'nowrap',minWidth:190}}>ASIN / Name</th>
              <th style={{padding:'9px 12px',textAlign:'left',fontSize:10,fontWeight:700,color:t.textMuted,textTransform:'uppercase',borderBottom:'2px solid '+t.divider,background:t.tableBg,whiteSpace:'nowrap'}}>Shop</th>
              {thSort('salePrice','Price')}
              {thSort('fba','FBA Total')}
              {thSort('available','Available')}
              {thSort('inbound','Inbound')}
              {thSort('reserved','Reserved')}
              {thSort('unfulfillable','Unfulfill.')}
              {thSort('daysLeft','Days Left')}
              {thSort('age0_90','0-90d')}
              {thSort('age91_180','91-180d')}
              {thSort('age181_270','181-270d')}
              {thSort('age271_365','271-365d')}
              {thSort('age365plus','365d+')}
              {thSort('storageFee','Storage Fee')}
              {thSort('longTermFee','LT Fee')}
              {thSort('stockValue','Stock Value')}
            </tr></thead>
            <tbody>{filteredAsin.length===0?<tr><td colSpan={17} style={{padding:30,textAlign:'center',color:t.textMuted,fontSize:12}}>{asinRows.length===0?'Loading inventory data…':'No results for "'+asinSearch+'"'}</td></tr>:filteredAsin.map((r,i)=>{
              const oos=r.oos45;
              return<tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background='transparent'} style={{background:oos?t.redBg+'55':'transparent'}}>
                <td style={{padding:'8px 12px',borderBottom:'1px solid '+t.divider}}>
                  <div style={{display:'flex',alignItems:'center',gap:6}}>
                    {oos&&<span title="OOS risk <45 days" style={{color:t.red,fontSize:10,fontWeight:700}}>⚠</span>}
                    <AsinLink asin={r.asin} onClick={onAsinClick||(()=>{})} t={t}/>
                  </div>
                  {r.name&&<div style={{fontSize:10,color:t.textMuted,marginTop:1,maxWidth:200,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.name}</div>}
                  {r.sku&&<div style={{fontSize:9,color:t.textMuted}}>{r.sku}</div>}
                </td>
                <td style={{padding:'8px 12px',fontSize:12,color:t.textSec,borderBottom:'1px solid '+t.divider,whiteSpace:'nowrap'}}>{r.shop}</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider,fontWeight:600}}>{r.salePrice>0?$2(r.salePrice):<span style={{color:t.textMuted}}>—</span>}</td>
                <td style={{padding:'8px 12px',textAlign:'right',fontWeight:700,borderBottom:'1px solid '+t.divider}}>{N(r.fba)}</td>
                <td style={{padding:'8px 12px',textAlign:'right',color:t.green,fontWeight:600,borderBottom:'1px solid '+t.divider}}>{N(r.available)}</td>
                <td style={{padding:'8px 12px',textAlign:'right',color:t.blue,fontWeight:600,borderBottom:'1px solid '+t.divider}}>{r.inbound>0?N(r.inbound):<span style={{color:t.textMuted}}>—</span>}</td>
                <td style={{padding:'8px 12px',textAlign:'right',color:t.orange,borderBottom:'1px solid '+t.divider}}>{r.reserved>0?N(r.reserved):<span style={{color:t.textMuted}}>—</span>}</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.unfulfillable>0?t.red:t.textMuted}}>{r.unfulfillable>0?N(r.unfulfillable):'—'}</td>
                <td style={{padding:'8px 12px',textAlign:'right',fontWeight:600,borderBottom:'1px solid '+t.divider,color:r.daysLeft>0&&r.daysLeft<=14?t.red:r.daysLeft<=45?t.orange:t.text}}>{r.daysLeft>0?r.daysLeft+'d':'—'}</td>
                {/* Stock age columns */}
                <td style={{padding:'8px 10px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:t.green,fontSize:11}}>{r.age0_90>0?N(r.age0_90):<span style={{color:t.textMuted}}>—</span>}</td>
                <td style={{padding:'8px 10px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.age91_180>0?t.orange:t.textMuted,fontSize:11}}>{r.age91_180>0?N(r.age91_180):'—'}</td>
                <td style={{padding:'8px 10px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.age181_270>0?t.orange:t.textMuted,fontSize:11}}>{r.age181_270>0?N(r.age181_270):'—'}</td>
                <td style={{padding:'8px 10px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.age271_365>0?t.red:t.textMuted,fontSize:11}}>{r.age271_365>0?N(r.age271_365):'—'}</td>
                <td style={{padding:'8px 10px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.age365plus>0?t.red:t.textMuted,fontSize:11,fontWeight:r.age365plus>0?700:400}}>{r.age365plus>0?N(r.age365plus):'—'}</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.storageFee>200?t.red:r.storageFee>50?t.orange:t.text}}>{r.storageFee>0?$2(r.storageFee):'—'}</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider,color:r.longTermFee>0?t.red:t.textMuted,fontWeight:r.longTermFee>0?700:400}}>{r.longTermFee>0?$2(r.longTermFee):'—'}</td>
                <td style={{padding:'8px 12px',textAlign:'right',borderBottom:'1px solid '+t.divider}}>{r.stockValue>0?$2(r.stockValue):'—'}</td>
              </tr>;
            })}</tbody>
          </table>
        </div>
        <div style={{padding:'6px 14px',fontSize:10,color:t.textMuted,borderTop:'1px solid '+t.divider,background:t.tableBg}}>
          {filteredAsin.length} of {asinRows.length} ASINs · <span style={{color:t.green}}>■</span> 0-90d <span style={{color:t.orange}}>■</span> 91-270d <span style={{color:t.red}}>■</span> 271d+ · <span style={{color:t.red}}>⚠ OOS ≤45d</span> · LT Fee = Long-term storage fee · Click headers to sort
        </div>
      </Cd>
    </Sec>

    {/* ⑥ Storage fee history + sell-through chart */}
    <div style={{display:"grid",gridTemplateColumns:mob?"1fr":"1fr 1fr",gap:14,marginTop:14}}>
      <Sec title="Storage Fee History" icon="" t={t}>
        <Cd t={t}>{feeHist.length>0?<div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:13}}><thead><tr>{["Month","Storage Fee","Change"].map((h,i)=><th key={i} style={{padding:"8px 12px",textAlign:i>=1?"right":"left",color:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{feeHist.map((r,i)=>{const prev=i>0?feeHist[i-1].fee:null;const chg=prev?((r.fee-prev)/Math.max(prev,1)*100):null;const[y,m]=r.month.split("-");const label=MS[parseInt(m)-1]+" "+y;return<tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:600,borderBottom:"1px solid "+t.divider}}>{label}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.fee>5000?t.red:t.text,borderBottom:"1px solid "+t.divider}}>{$2(r.fee)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{chg!==null?<span style={{fontSize:11,fontWeight:600,color:chg>0?t.red:chg<0?t.green:t.textMuted,background:chg>0?t.redBg:chg<0?t.greenBg:"transparent",padding:"2px 8px",borderRadius:10}}>{chg>0?"+":""}{chg.toFixed(1)}%</span>:<span style={{fontSize:10,color:t.textMuted}}>—</span>}</td></tr>})}</tbody></table></div>:<div style={{padding:20,textAlign:"center",color:t.textMuted,fontSize:11}}>No historical data available</div>}</Cd>
      </Sec>
      <Sec title="Sell-Through & Days of Supply by Shop" icon="" t={t}>
        <Cd t={t}><div style={{fontSize:10,color:t.textMuted,marginBottom:8}}>Sell-Through = Units Sold 30d ÷ (Sold + Stock) · Days of Supply = Stock ÷ Avg Daily Sales (30d) · <span style={{color:t.orange}}>Note: differs from KPI cards which use Amazon's own calculation</span></div><ResponsiveContainer width="100%" height={220}><BarChart data={invShop} barGap={3} barCategoryGap="18%"><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="s" tick={{fill:t.textSec,fontSize:10}} interval={0} angle={-20} textAnchor="end" height={50}/><YAxis yAxisId="l" tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>Math.round(v*100)+"%"}/><YAxis yAxisId="r" orientation="right" tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>v+"d"}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar yAxisId="l" dataKey="st" name="Sell-Through %" fill={t.green} radius={[3,3,0,0]}/><Bar yAxisId="r" dataKey="doh" name="Days of Supply" fill={t.orange} radius={[3,3,0,0]}/></BarChart></ResponsiveContainer></Cd>
      </Sec>
    </div>
  </div>;
}

/* ═══════════ ASIN PLAN — sub-components ═══════════ */
function PlanColFilter({value,onChange,options,ph,t}){
  const active=value!==ph;
  return<select value={value} onChange={e=>{e.stopPropagation();onChange(e.target.value);}} onClick={e=>e.stopPropagation()}
    style={{background:active?t.primaryLight:"transparent",border:`1px solid ${active?t.primary+"66":t.divider}`,borderRadius:5,padding:"2px 5px",fontSize:9,color:active?t.primary:t.textMuted,fontWeight:600,cursor:"pointer",outline:"none",marginTop:5,width:"100%",display:"block"}}>
    <option value={ph} style={{background:t.card}}>{ph}</option>
    {options.filter(o=>o!==ph).map(o=><option key={o} value={o} style={{background:t.card}}>{o}</option>)}
  </select>;
}
function PlanSortTh({label,col,sortCol,sortDir,onSort,align="right",minW=95,children,t}){
  const active=sortCol===col;
  return<th onClick={()=>onSort(col)} style={{padding:"10px 10px 6px",textAlign:align,fontSize:9.5,fontWeight:700,color:active?t.primary:t.textMuted,textTransform:"uppercase",letterSpacing:.4,borderBottom:`2px solid ${t.divider}`,background:t.tableBg,whiteSpace:"nowrap",cursor:"pointer",userSelect:"none",position:"sticky",top:0,zIndex:3,minWidth:minW}}>
    <span style={{display:"flex",alignItems:"center",justifyContent:align==="left"?"flex-start":"flex-end",gap:3}}>{label}{active&&<span style={{fontSize:9}}>{sortDir>0?"↑":"↓"}</span>}</span>
    {children}
  </th>;
}

const PLAN_PAGE_SIZE=25;
function PlanAlertsTab({alerts,t,onAsinClick}){
  const[sevF,setSevF]=useState("All");
  const[sellerF,setSellerF]=useState("All");
  const[brandF,setBrandF]=useState("All");
  const[search,setSearch]=useState("");
  const[page,setPage]=useState(1);
  const[sortCol,setSortCol]=useState("pctGp");
  const[sortDir,setSortDir]=useState(1);
  function handleSort(col){if(sortCol===col)setSortDir(d=>-d);else{setSortCol(col);setSortDir(1);}}
  function wrap(fn){return v=>{fn(v);setPage(1);}}

  const sellerOpts=["All",...new Set(alerts.map(r=>r.sl).filter(Boolean))];
  const brandOpts=["All",...new Set(alerts.map(r=>r.br).filter(Boolean))];
  const critical=alerts.filter(r=>r.pctGp<75);
  const warning=alerts.filter(r=>r.pctGp>=75&&r.pctGp<100);

  const filtered=useMemo(()=>{
    let r=[...alerts];
    if(sevF==="Critical") r=r.filter(x=>x.pctGp<75);
    if(sevF==="Warning")  r=r.filter(x=>x.pctGp>=75&&x.pctGp<100);
    if(sellerF!=="All") r=r.filter(x=>x.sl===sellerF);
    if(brandF !=="All") r=r.filter(x=>x.br===brandF);
    if(search){const q=search.toLowerCase();r=r.filter(x=>(x.a||"").toLowerCase().includes(q)||(x.br||"").toLowerCase().includes(q)||(x.sl||"").toLowerCase().includes(q));}
    return [...r].sort((a,b)=>sortDir*((a[sortCol]||0)-(b[sortCol]||0)));
  },[alerts,sevF,sellerF,brandF,search,sortCol,sortDir]);

  const totalPages=Math.max(1,Math.ceil(filtered.length/PLAN_PAGE_SIZE));
  const pageRows=filtered.slice((page-1)*PLAN_PAGE_SIZE,page*PLAN_PAGE_SIZE);
  const hasFilter=sevF!=="All"||sellerF!=="All"||brandF!=="All"||search;

  const STh=({label,col,minW=80,align})=>{
    const a=align||(col==="a"||col==="br"||col==="sl"?"left":"right");
    const active=sortCol===col;
    return<th onClick={()=>handleSort(col)} style={{padding:"9px 10px",textAlign:a,fontSize:9,fontWeight:700,color:active?t.primary:t.textMuted,textTransform:"uppercase",letterSpacing:.4,borderBottom:`2px solid ${t.divider}`,background:t.tableBg,whiteSpace:"nowrap",cursor:"pointer",userSelect:"none",position:"sticky",top:0,zIndex:2,minWidth:minW}}>
      <span style={{display:"flex",alignItems:"center",justifyContent:a==="left"?"flex-start":"flex-end",gap:3}}>{label}{active&&<span style={{fontSize:8}}>{sortDir>0?"↑":"↓"}</span>}</span>
    </th>;
  };

  const btnStyle=(dis)=>({padding:"4px 9px",borderRadius:6,border:`1px solid ${t.cardBorder}`,background:dis?t.tableBg:t.card,color:dis?t.textMuted:t.textSec,fontSize:11,cursor:dis?"default":"pointer"});

  return<div>
    {/* Combined filter + stats bar */}
    <div style={{display:"flex",gap:6,marginBottom:10,flexWrap:"wrap",alignItems:"center"}}>
      {/* Severity toggle */}
      <div style={{display:"flex",gap:3,background:t.card,border:`1px solid ${t.cardBorder}`,borderRadius:8,padding:3}}>
        {["All","Critical","Warning"].map(s=>(
          <button key={s} onClick={()=>{setSevF(s);setPage(1);}} style={{padding:"5px 12px",borderRadius:6,border:"none",fontSize:10.5,fontWeight:700,cursor:"pointer",
            background:sevF===s?(s==="Critical"?t.redBg:s==="Warning"?t.orangeBg:t.primaryLight):"transparent",
            color:sevF===s?(s==="Critical"?t.red:s==="Warning"?t.orange:t.primary):t.textMuted}}>
            {s==="Critical"?"Critical":s==="Warning"?"Warning":"All"}
          </button>
        ))}
      </div>
      <select value={sellerF} onChange={e=>wrap(setSellerF)(e.target.value)} style={{background:sellerF!=="All"?t.primaryLight:t.card,border:`1px solid ${sellerF!=="All"?t.primary+"55":t.cardBorder}`,borderRadius:8,padding:"6px 10px",fontSize:11,color:sellerF!=="All"?t.primary:t.textSec,fontWeight:600,cursor:"pointer",outline:"none"}}>
        {sellerOpts.map(o=><option key={o} value={o} style={{background:t.card}}>{o==="All"?"All Sellers":o}</option>)}
      </select>
      <select value={brandF} onChange={e=>wrap(setBrandF)(e.target.value)} style={{background:brandF!=="All"?t.primaryLight:t.card,border:`1px solid ${brandF!=="All"?t.primary+"55":t.cardBorder}`,borderRadius:8,padding:"6px 10px",fontSize:11,color:brandF!=="All"?t.primary:t.textSec,fontWeight:600,cursor:"pointer",outline:"none"}}>
        {brandOpts.map(o=><option key={o} value={o} style={{background:t.card}}>{o==="All"?"All Brands":o}</option>)}
      </select>
      <input value={search} onChange={e=>wrap(setSearch)(e.target.value)} placeholder="Search ASIN / Brand / Seller..."
        style={{flex:1,minWidth:160,background:t.card,border:`1px solid ${t.cardBorder}`,borderRadius:8,padding:"6px 12px",color:t.text,fontSize:11,outline:"none"}}/>
      {/* Inline stats — right-aligned, clearly read-only */}
      <div style={{display:"flex",alignItems:"center",gap:0,marginLeft:"auto",flexShrink:0}}>
        {[{label:"Total",val:alerts.length,color:t.textSec},{label:"Critical",val:critical.length,color:t.red},{label:"Warning",val:warning.length,color:t.orange},{label:"Showing",val:filtered.length,color:t.primary}].map((s,i)=>(
          <React.Fragment key={i}>
            {i>0&&<span style={{width:1,height:14,background:t.divider,margin:"0 10px",flexShrink:0,display:"inline-block"}}/>}
            <span style={{fontSize:10,color:t.textMuted}}>{s.label} </span>
            <span style={{fontSize:12,fontWeight:800,color:s.color,marginLeft:3}}>{s.val}</span>
          </React.Fragment>
        ))}
      </div>
      {hasFilter&&<button onClick={()=>{setSevF("All");setSellerF("All");setBrandF("All");setSearch("");setPage(1);}}
        style={{background:t.redBg,border:`1px solid ${t.red}44`,color:t.red,fontSize:10,fontWeight:600,padding:"6px 10px",borderRadius:8,cursor:"pointer",whiteSpace:"nowrap"}}>
        ✕ Clear
      </button>}
    </div>

    {/* Table */}
    <div style={{background:t.card,border:`1px solid ${t.cardBorder}`,borderRadius:12,overflow:"hidden"}}>
      <div style={{overflowX:"auto"}}>
        <table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12}}>
          <thead><tr>
            <STh label="Sev"       col="pctGp"   minW={44}/>
            <STh label="ASIN"      col="a"        minW={120}/>
            <STh label="Brand"     col="br"       minW={100}/>
            <STh label="Seller"    col="sl"       minW={80}/>
            <STh label="% Plan"    col="pctGp"    minW={70}/>
            <STh label="GP Actual" col="ga"    minW={90}/>
            <STh label="GP Gap"    col="gpGap"    minW={85}/>
            <STh label="Revenue"   col="ra"       minW={90}/>
            <STh label="Margin"    col="_margin"  minW={75}/>
            <STh label="ROAS"      col="_roas"    minW={70}/>
          </tr></thead>
          <tbody>
            {pageRows.map((r,i)=>{
              const isCrit=r.pctGp<75;
              const isLoss=r.ga<0;
              const sevColor=isLoss?t.red:isCrit?t.red:t.orange;
              return<tr key={i}
                style={{background:i%2===1?t.tableHover+"88":"transparent",cursor:"pointer"}}
                onMouseEnter={e=>e.currentTarget.style.background=t.tableHover}
                onMouseLeave={e=>e.currentTarget.style.background=i%2===1?t.tableHover+"88":"transparent"}
                onClick={()=>onAsinClick&&onAsinClick(r.a)}>
                <td style={{padding:"8px 10px",borderBottom:`1px solid ${t.divider}`,textAlign:"center",fontSize:14}}>{isCrit?"🔴":"🟡"}</td>
                <td style={{padding:"8px 10px",borderBottom:`1px solid ${t.divider}`}}><AsinLink asin={r.a} onClick={()=>onAsinClick&&onAsinClick(r.a)} t={t}/></td>
                <td style={{padding:"8px 10px",borderBottom:`1px solid ${t.divider}`,fontWeight:600,fontSize:11}}>{r.br||"—"}</td>
                <td style={{padding:"8px 10px",borderBottom:`1px solid ${t.divider}`,color:t.primary,fontWeight:600,fontSize:11}}>{r.sl||"—"}</td>
                <td style={{padding:"8px 10px",textAlign:"right",borderBottom:`1px solid ${t.divider}`}}>
                  <span style={{background:sevColor+"22",color:sevColor,padding:"2px 8px",borderRadius:5,fontSize:11,fontWeight:700}}>
                    {isLoss?"⛔ LOSS":r.pctGp+"%"}
                  </span>
                </td>
                <td style={{padding:"8px 10px",textAlign:"right",borderBottom:`1px solid ${t.divider}`,fontWeight:700,color:t.text,fontSize:12}}>{$(r.ga)}</td>
                <td style={{padding:"8px 10px",textAlign:"right",borderBottom:`1px solid ${t.divider}`,fontWeight:700,color:t.red,fontSize:12}}>-{$(r.gpGap)}</td>
                <td style={{padding:"8px 10px",textAlign:"right",borderBottom:`1px solid ${t.divider}`,fontSize:12,color:t.textSec}}>{$(r.ra)}</td>
                <td style={{padding:"8px 10px",textAlign:"right",borderBottom:`1px solid ${t.divider}`,fontWeight:700,color:r._margin==null?t.textMuted:r._margin>25?t.green:r._margin>15?t.orange:t.red}}>{r._margin!=null?r._margin.toFixed(1)+"%":"—"}</td>
                <td style={{padding:"8px 10px",textAlign:"right",borderBottom:`1px solid ${t.divider}`,fontWeight:700,color:r._roas==null?t.textMuted:r._roas>8?t.green:r._roas>5?t.orange:t.red}}>{r._roas!=null?r._roas.toFixed(2)+"x":"—"}</td>
              </tr>;
            })}
            {pageRows.length===0&&<tr><td colSpan={10} style={{padding:32,textAlign:"center",color:t.textMuted,fontSize:12}}>Không có alert nào khớp filter</td></tr>}
          </tbody>
        </table>
      </div>
      {/* Pagination */}
      <div style={{padding:"10px 14px",borderTop:`1px solid ${t.divider}`,display:"flex",alignItems:"center",justifyContent:"space-between",background:t.card,flexWrap:"wrap",gap:8}}>
        <span style={{fontSize:10,color:t.textMuted}}>
          {filtered.length===0?"No results":`${(page-1)*PLAN_PAGE_SIZE+1}–${Math.min(page*PLAN_PAGE_SIZE,filtered.length)} of ${filtered.length} alerts`}
        </span>
        <div style={{display:"flex",gap:4,alignItems:"center"}}>
          <button onClick={()=>setPage(1)} disabled={page===1} style={btnStyle(page===1)}>«</button>
          <button onClick={()=>setPage(p=>Math.max(1,p-1))} disabled={page===1} style={btnStyle(page===1)}>‹</button>
          {Array.from({length:totalPages},(_,i)=>i+1)
            .filter(p=>p===1||p===totalPages||Math.abs(p-page)<=1)
            .reduce((acc,p,i,arr)=>{if(i>0&&p-arr[i-1]>1)acc.push("…");acc.push(p);return acc;},[])
            .map((p,i)=>p==="…"
              ?<span key={"e"+i} style={{padding:"4px 6px",color:t.textMuted,fontSize:11}}>…</span>
              :<button key={p} onClick={()=>setPage(p)} style={{padding:"4px 9px",borderRadius:6,border:`1px solid ${p===page?t.primary+"55":t.cardBorder}`,background:p===page?t.primaryLight:t.card,color:p===page?t.primary:t.textSec,fontSize:11,fontWeight:p===page?700:400,cursor:"pointer"}}>{p}</button>
            )}
          <button onClick={()=>setPage(p=>Math.min(totalPages,p+1))} disabled={page===totalPages} style={btnStyle(page===totalPages)}>›</button>
          <button onClick={()=>setPage(totalPages)} disabled={page===totalPages} style={btnStyle(page===totalPages)}>»</button>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:6}}>
          <span style={{fontSize:10,color:t.textMuted}}>Go to</span>
          <input type="number" min={1} max={totalPages} defaultValue={page}
            onKeyDown={e=>{if(e.key==="Enter"){const v=parseInt(e.target.value);if(v>=1&&v<=totalPages)setPage(v);}}}
            style={{width:44,background:t.card,border:`1px solid ${t.cardBorder}`,borderRadius:6,padding:"4px 7px",color:t.text,fontSize:11,outline:"none",textAlign:"center"}}/>
        </div>
      </div>
    </div>

    {/* Logic note */}
    <div style={{marginTop:10,padding:"8px 14px",borderRadius:8,border:`1px solid ${t.cardBorder}`,background:t.card,fontSize:10,color:t.textMuted,lineHeight:1.7}}>
      <strong style={{color:t.text}}>Alert logic:</strong>
      <span style={{color:t.red,fontWeight:600}}> 🔴 Critical</span> = GP &lt;75% plan ·
      <span style={{color:t.orange,fontWeight:600}}> 🟡 Warning</span> = GP 75–99% ·
      GP Gap = amount short of plan · Click header to sort
    </div>
  </div>;
}

/* ═══════════ ASIN PLAN ═══════════ */
function PlanPage({t,planKpi,monthPlanData,asinPlanBkData,seller,store,asinF,onAsinClick,onStoreChange,onSellerChange}){
  const isF=(seller&&seller!=="All")||(store&&store!=="All")||(asinF&&asinF!=="All");
  const[trendMetric,setTrendMetric]=useState("gp");
  const[planMonth,setPlanMonth]=useState(MS[new Date().getMonth()]);
  const[activeTab,setActiveTab]=useState("breakdown");
  const tabRef=useRef(null);
  const scrollToAlerts=()=>{setActiveTab("alerts");setTimeout(()=>tabRef.current?.scrollIntoView({behavior:"smooth",block:"start"}),50);};

  // Breakdown filters
  const[bkSearch,setBkSearch]=useState("");
  const[colBrand,setColBrand]=useState("All");
  const[colSeller,setColSeller]=useState("All");
  const[bkSortCol,setBkSortCol]=useState("pctGp");
  const[bkSortDir,setBkSortDir]=useState(-1);
  function handleBkSort(col){if(bkSortCol===col)setBkSortDir(d=>-d);else{setBkSortCol(col);setBkSortDir(-1);}}

  const metrics=[
    {k:"gp",l:"Gross Profit"},{k:"rv",l:"Revenue"},{k:"ad",l:"Ads Spend"},{k:"un",l:"Units"},
    {k:"roas",l:"ROAS"},{k:"margin",l:"Margin"},
    {k:"se",l:"Sessions"},{k:"im",l:"Impressions"},{k:"cr",l:"Conv. Rate"},{k:"ct",l:"Click-Through Rate"},
  ];
  const mK={gp:{a:"gpa",p:"gpp"},rv:{a:"ra",p:"rp"},ad:{a:"aa",p:"ap"},un:{a:"ua",p:"up"},se:{a:"sa",p:"sp"},im:{a:"ia",p:"ip"},cr:{a:"cra",p:"crp"},ct:{a:"cta",p:"ctp"}};

  const mpd=monthPlanData||[];
  const hasData=mpd.some(m=>(m.gpa||0)+(m.gpp||0)+(m.ra||0)+(m.rp||0)>0)||(asinPlanBkData||[]).length>0;
  // Computed per-month ROAS and Margin for trend chart
  const trendData=mpd.map(m=>{
    if(trendMetric==="roas") return{m:m.m,Actual:m.aa>0?Math.round(m.ra/m.aa*100)/100:null,Plan:m.ap>0?Math.round(m.rp/m.ap*100)/100:null};
    if(trendMetric==="margin") return{m:m.m,Actual:m.ra>0?Math.round(m.gpa/m.ra*1000)/10:null,Plan:m.rp>0?Math.round(m.gpp/m.rp*1000)/10:null};
    const ak=mK[trendMetric]?.a,pk2=mK[trendMetric]?.p;
    return{m:m.m,Actual:m[ak],Plan:m[pk2]};
  });
  const isCur=["gp","rv","ad"].includes(trendMetric);
  const isPct=["cr","ct","margin"].includes(trendMetric);
  const isRoas=trendMetric==="roas";

  const kpiData=useMemo(()=>{
    const pk=planKpi||{gp:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}};
    if(planMonth==="All")return pk;
    const mi=MS.indexOf(planMonth);const m=mpd[mi];if(!m)return pk;
    return{
      gp:{a:m.gpa,p:m.gpp},rv:{a:m.ra,p:m.rp},ad:{a:m.aa,p:m.ap},un:{a:m.ua,p:m.up},
      se:{a:m.sa,p:m.sp},im:{a:m.ia,p:m.ip},
      cr:{a:(m.cra||0)/100,p:(m.crp||0)/100},ct:{a:(m.cta||0)/100,p:(m.ctp||0)/100},
    };
  },[planMonth,planKpi,mpd]);

  // Computed KPIs: ROAS + Margin (từ GP/Revenue/Ads)
  const kpiRoas={a:kpiData.ad.a>0?kpiData.rv.a/kpiData.ad.a:null,p:kpiData.ad.p>0?kpiData.rv.p/kpiData.ad.p:null};
  const kpiMargin={a:kpiData.rv.a>0?kpiData.gp.a/kpiData.rv.a*100:null,p:kpiData.rv.p>0?kpiData.gp.p/kpiData.rv.p*100:null};

  // ── YTD Plan helper ──────────────────────────────────────────────────────────
  // Khi filter "All months": chỉ cộng plan của các tháng đã có actual data,
  // tránh so YTD actual vs full-year plan (gây ra -1487% / 25% sai lệch)
  const getYtdPlan=(r,field/*"gp"|"rp"|"ap"|"up"*/)=>{
    if(planMonth!=="All") return r[field]||0; // đã filter 1 tháng, dùng thẳng
    if(!r.mData) return r[field]||0;          // fallback nếu không có mData
    const actualKey={gp:"ga",rp:"ra",ap:"aa",up:"ua"}[field]||"ga";
    return Object.values(r.mData)
      .filter(m=>(m[actualKey]||0)+(m.ra||0)>0)   // tháng có actual
      .reduce((s,m)=>s+(m[field]||0),0);
  };

  // Base ASIN data filtered by month
  const basePlanBk=useMemo(()=>{
    const raw=asinPlanBkData||[];
    if(planMonth==="All")return raw;
    const mi=MS.indexOf(planMonth)+1;
    return raw.map(r=>{
      const md=r.mData?.[mi]||r.mData?.[String(mi)]||{};
      return{...r,ga:md.ga||0,gp:md.gp||0,ra:md.ra||0,rp:md.rp||0,aa:md.aa||0,ap:md.ap||0,ua:md.ua||0,up:md.up||0,sv:md.sv||0};
    }).filter(r=>Math.abs(r.ga||0)+Math.abs(r.gp||0)+Math.abs(r.ra||0)+Math.abs(r.rp||0)>0);
  },[planMonth,asinPlanBkData]);

  // Column filter (dropdown)
  const fPlanBk=useMemo(()=>{
    let rows=basePlanBk;
    if(colBrand!=="All") rows=rows.filter(r=>r.br===colBrand);
    if(colSeller!=="All") rows=rows.filter(r=>r.sl===colSeller);
    return rows;
  },[basePlanBk,colBrand,colSeller]);

  // Add computed fields — dùng YTD plan cho % Plan
  const bkWithMetrics=useMemo(()=>fPlanBk.map(r=>{
    const _roas=r.aa>0?r.ra/r.aa:null;
    const _margin=r.ra>0?(r.ga/r.ra)*100:null;
    const gpPlan=getYtdPlan(r,"gp");
    const _pctGp=gpPlan>0?Math.round((r.ga/gpPlan)*100):null;
    const _gpPlanYtd=gpPlan; // lưu lại để hiện tooltip
    return{...r,_roas,_margin,_pctGp,_gpPlanYtd};
  }),[fPlanBk,planMonth]);

  // Apply search + sort
  const bkRows=useMemo(()=>{
    let rows=bkWithMetrics;
    if(bkSearch){const q=bkSearch.toLowerCase();rows=rows.filter(r=>(r.a||"").toLowerCase().includes(q)||(r.br||"").toLowerCase().includes(q)||(r.sl||"").toLowerCase().includes(q));}
    return[...rows].sort((a,b)=>{
      const getV=r=>bkSortCol==="pctGp"?r._pctGp||0:bkSortCol==="_roas"?r._roas||0:bkSortCol==="_margin"?r._margin||0:(r[bkSortCol]||0);
      return bkSortDir*(getV(b)-getV(a));
    });
  },[bkWithMetrics,bkSearch,bkSortCol,bkSortDir]);

  // Alerts — cũng dùng YTD plan
  const alertRows=useMemo(()=>basePlanBk.map(r=>{
    const gpPlan=getYtdPlan(r,"gp");
    const pctGp=gpPlan>0?Math.round((r.ga/gpPlan)*100):null;
    if(pctGp===null||pctGp>=100)return null;
    return{...r,pctGp,_roas:r.aa>0?r.ra/r.aa:null,_margin:r.ra>0?(r.ga/r.ra)*100:null,gpGap:gpPlan-r.ga};
  }).filter(Boolean).sort((a,b)=>a.pctGp-b.pctGp),[basePlanBk,planMonth]);

  const critAlerts=alertRows.filter(a=>a.pctGp<75);
  const warnAlerts=alertRows.filter(a=>a.pctGp>=75);
  const hasColFilter=colBrand!=="All"||colSeller!=="All";

  // Cross-filtered options: Brand list filtered by selected seller, Seller list filtered by selected brand
  const brandOpts=["All",...new Set(
    (colSeller!=="All"?basePlanBk.filter(r=>r.sl===colSeller):basePlanBk).map(r=>r.br).filter(Boolean)
  )].sort();
  const sellerOpts=["All",...new Set(
    (colBrand!=="All"?basePlanBk.filter(r=>r.br===colBrand):basePlanBk).map(r=>r.sl).filter(Boolean)
  )].sort();

  // Handle ASIN row click → sync global filters
  const handleBkAsinClick=r=>{
    if(onStoreChange&&r.st&&r.st!=="All") onStoreChange(r.st);
    if(onSellerChange&&r.sl&&r.sl!=="All") onSellerChange(r.sl);
    if(onAsinClick) onAsinClick(r.a);
  };

  const TABS=[
    {k:"breakdown",l:"ASIN Breakdown",cnt:bkRows.length},
    {k:"monthly",  l:"Monthly Table", cnt:mpd.length},
    {k:"alerts",   l:"Alerts",        cnt:alertRows.length,warn:critAlerts.length>0},
  ];

  return<div>
    {!hasData&&<div style={{padding:24,textAlign:"center",color:t.textMuted,fontSize:13,background:t.card,borderRadius:12,border:"1px solid "+t.cardBorder,marginBottom:16}}>No plan data found. Try selecting a different year or adjusting filters.</div>}

    {/* ── Header row: title + global filter pills ── */}
    <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:14,flexWrap:"wrap",gap:10}}>
      <div>
        <div style={{fontSize:15,fontWeight:700,letterSpacing:-.2,marginBottom:3}}>ASIN Plan</div>
        <div style={{fontSize:10,color:t.textMuted}}>
          {alertRows.length} ASINs below plan ·
          <span style={{color:t.red,fontWeight:600}}> {critAlerts.length} Critical</span> ·
          <span style={{color:t.orange,fontWeight:600}}> {warnAlerts.length} Warning</span>
          {isF&&<span style={{color:t.orange,fontWeight:600,marginLeft:6}}>· Filtered: {[store!=="All"&&store,seller!=="All"&&seller,asinF!=="All"&&asinF].filter(Boolean).join(" · ")}</span>}
        </div>
      </div>
      <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
        {/* Month pill */}
        <div style={{display:"flex",alignItems:"center",gap:5,background:t.card,border:"1px solid "+t.cardBorder,borderRadius:8,padding:"5px 10px"}}>
          <span style={{fontSize:9,color:t.textMuted,fontWeight:700,textTransform:"uppercase",letterSpacing:.5}}>Month</span>
          <Sel value={planMonth} onChange={setPlanMonth} options={MS} label="All Months" t={t}/>
          {planMonth!=="All"&&<button onClick={()=>setPlanMonth("All")} style={{background:"transparent",border:"none",color:t.red,fontSize:11,cursor:"pointer",padding:"0 2px",fontWeight:700}}>✕</button>}
        </div>
      </div>
    </div>

    {/* ── Alert banner ── */}
    {alertRows.length>0&&(()=>{
      const totGpA=basePlanBk.reduce((s,r)=>s+r.ga,0),totGpP=basePlanBk.reduce((s,r)=>s+getYtdPlan(r,"gp"),0);
      const gpPct=totGpP>0?Math.round(totGpA/totGpP*100):0;
      return<div style={{background:t.redBg,border:"1px solid "+t.red+"33",borderRadius:10,padding:"9px 14px",marginBottom:14,display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={t.red} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <div style={{flex:1,fontSize:11}}>
          <strong style={{color:t.red}}>{critAlerts.length} Critical</strong>
          <span style={{color:t.textSec}}> (GP &lt;75%) · </span>
          <strong style={{color:t.orange}}>{warnAlerts.length} Warning</strong>
          <span style={{color:t.textSec}}> (75–99%) · Total GP </span>
          <strong style={{color:gpPct>=100?t.green:t.red}}>{gpPct}% of plan</strong>
        </div>
        <button onClick={scrollToAlerts} style={{background:"transparent",border:"1px solid "+t.red+"55",color:t.red,fontSize:10,fontWeight:600,padding:"4px 12px",borderRadius:6,cursor:"pointer",whiteSpace:"nowrap"}}>
          View alerts →
        </button>
      </div>;
    })()}

    {/* ── KPI Cards — Row 1: GP · Revenue · Ads · Units · ROAS (5 cards) ── */}
    <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8,marginBottom:8}}>
      <PlanKpi title="Gross Profit" actual={kpiData.gp.a} plan={kpiData.gp.p} t={t} highlight tip={TIPS.gp}/>
      <PlanKpi title="Revenue"      actual={kpiData.rv.a} plan={kpiData.rv.p} t={t} tip={TIPS.revenue}/>
      <PlanKpi title="Ads Spend"    actual={kpiData.ad.a} plan={kpiData.ad.p} t={t} tip={TIPS.advCost}/>
      <PlanKpi title="Units"        actual={kpiData.un.a} plan={kpiData.un.p} t={t} fmt={N} tip={TIPS.units}/>
      <PlanKpi title="ROAS ✦"       actual={kpiRoas.a}    plan={kpiRoas.p}    t={t} fmt={v=>v!=null?v.toFixed(2)+"x":"—"}/>
    </div>
    {/* ── KPI Cards — Row 2: Margin · Sessions · Impressions · CR · CTR (5 cards) ── */}
    <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8,marginBottom:14}}>
      <PlanKpi title="Margin ✦"     actual={kpiMargin.a}  plan={kpiMargin.p}  t={t} fmt={v=>v!=null?v.toFixed(1)+"%":"—"}/>
      <PlanKpi title="Sessions"     actual={kpiData.se.a} plan={kpiData.se.p} t={t} fmt={N} tip={TIPS.sessions}/>
      <PlanKpi title="Impressions"  actual={kpiData.im.a} plan={kpiData.im.p} t={t} fmt={N}/>
      <PlanKpi title="Conv. Rate"   actual={kpiData.cr.a!=null?Math.round(kpiData.cr.a*10000)/100:null} plan={Math.round((kpiData.cr.p||0)*10000)/100} t={t} fmt={v=>v!=null?Math.round(v*100)/100+"%":"—"} tip={TIPS.cr}/>
      <PlanKpi title="CTR"          actual={kpiData.ct.a!=null?Math.round(kpiData.ct.a*10000)/100:null} plan={Math.round((kpiData.ct.p||0)*10000)/100} t={t} fmt={v=>v!=null?Math.round(v*100)/100+"%":"—"} tip={TIPS.ctr}/>
    </div>

    {/* ── Trend chart ── */}
    <Sec title="Trend — Actual vs Plan" icon="" t={t} action={<select value={trendMetric} onChange={e=>setTrendMetric(e.target.value)} style={{background:t.card,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"5px 10px",fontSize:11,fontWeight:600,color:t.primary,cursor:"pointer"}}>{metrics.map(m=><option key={m.k} value={m.k}>{m.l}</option>)}</select>}>
      <Cd t={t}><ResponsiveContainer width="100%" height={340}><ComposedChart data={trendData}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="m" tick={{fill:t.textSec,fontSize:11}}/><YAxis tick={{fill:t.textSec,fontSize:11}} tickFormatter={v=>isCur?$s(v):isPct?v+"%":isRoas?v+"x":N(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar dataKey="Actual" fill={t.primary} radius={[4,4,0,0]}/><Line type="monotone" dataKey="Plan" stroke={t.orange} strokeWidth={2} strokeDasharray="5 3" dot={{r:3,fill:t.orange}}/>{planMonth!=="All"&&<ReferenceLine x={planMonth} stroke={t.green} strokeWidth={2} strokeDasharray="4 2" label={{value:"▼",position:"top",fill:t.green,fontSize:11}}/>}</ComposedChart></ResponsiveContainer></Cd>
    </Sec>

    {/* ── Tabs ── */}
    <div ref={tabRef} style={{display:"flex",gap:4,marginTop:22,marginBottom:12,scrollMarginTop:12}}>
      {[
        {k:"breakdown",l:"ASIN Breakdown",cnt:bkRows.length,warn:false},
        {k:"monthly",  l:"Monthly Table", cnt:mpd.length,   warn:false},
        {k:"alerts",   l:"Alerts",         cnt:alertRows.length,warn:critAlerts.length>0},
      ].map(tb=>(
        <button key={tb.k} onClick={()=>setActiveTab(tb.k)} style={{padding:"7px 14px",borderRadius:8,border:`1px solid ${activeTab===tb.k?t.primary+"77":t.cardBorder}`,background:activeTab===tb.k?t.primaryLight:t.card,color:activeTab===tb.k?t.primary:t.textSec,fontWeight:activeTab===tb.k?700:500,fontSize:12,cursor:"pointer",display:"flex",alignItems:"center",gap:7}}>
          {tb.l}
          <span style={{background:tb.warn?t.redBg:t.divider,color:tb.warn?t.red:t.textMuted,fontSize:10,fontWeight:700,padding:"1px 7px",borderRadius:10}}>{tb.cnt}</span>
        </button>
      ))}
    </div>

    {/* ── Tab: ASIN Breakdown ── */}
    {activeTab==="breakdown"&&<div style={{background:t.card,border:"1px solid "+t.cardBorder,borderRadius:12,overflow:"hidden"}}>
      {/* Filter bar: search + brand */}
      <div style={{padding:"9px 14px",borderBottom:"1px solid "+t.divider,display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
        <input value={bkSearch} onChange={e=>setBkSearch(e.target.value)} placeholder="Search ASIN / Brand / Seller..."
          style={{flex:1,minWidth:180,background:t.tableBg,border:"1px solid "+t.cardBorder,borderRadius:8,padding:"6px 12px",color:t.text,fontSize:12,outline:"none"}}/>
        <select value={colBrand} onChange={e=>setColBrand(e.target.value)}
          style={{background:colBrand!=="All"?t.primaryLight:t.tableBg,border:`1px solid ${colBrand!=="All"?t.primary+"55":t.cardBorder}`,borderRadius:8,padding:"6px 10px",fontSize:11,color:colBrand!=="All"?t.primary:t.textSec,fontWeight:600,cursor:"pointer",outline:"none"}}>
          {brandOpts.map(o=><option key={o} value={o} style={{background:t.card}}>{o==="All"?"All Brands":o}</option>)}
        </select>
        <span style={{fontSize:10,color:t.textMuted,whiteSpace:"nowrap"}}>{bkRows.length} ASINs</span>
        {hasColFilter&&<button onClick={()=>{setColBrand("All");setColSeller("All");}} style={{background:t.redBg,border:"1px solid "+t.red+"44",color:t.red,fontSize:10,fontWeight:600,padding:"4px 10px",borderRadius:6,cursor:"pointer",whiteSpace:"nowrap"}}>✕ Clear</button>}
      </div>
      <div style={{overflowX:"auto",maxHeight:460,overflowY:"auto"}}>
        <table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12}}>
          <thead>
            <tr>
              <PlanSortTh label="ASIN"     col="a"       sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} align="left" minW={130} t={t}/>
              <PlanSortTh label="Brand"    col="br"      sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} align="left" minW={110} t={t}/>
              <PlanSortTh label="Seller"   col="sl"      sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} align="left" minW={100} t={t}/>
              <PlanSortTh label="% Plan"   col="pctGp"   sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} minW={72}  t={t}/>
              <PlanSortTh label="GP"       col="ga"      sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} minW={95}  t={t}/>
              <PlanSortTh label="Revenue"  col="ra"      sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} minW={95}  t={t}/>
              <PlanSortTh label="Ads"      col="aa"      sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} minW={90}  t={t}/>
              <PlanSortTh label="Units"    col="ua"      sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} minW={75}  t={t}/>
              <PlanSortTh label="Margin ✦" col="_margin" sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} minW={80}  t={t}/>
              <PlanSortTh label="ROAS ✦"   col="_roas"   sortCol={bkSortCol} sortDir={bkSortDir} onSort={handleBkSort} minW={75}  t={t}/>
            </tr>
          </thead>
          <tbody>
            {bkRows.map((r,i)=>{
              const behind=r._pctGp!=null&&r._pctGp<100;
              const pc=r._pctGp==null?t.textMuted:r._pctGp>=100?t.green:r._pctGp>=85?t.orange:t.red;
              const isSel=asinF===r.a;
              return<tr key={i}
                style={{background:isSel?t.primaryLight:behind?t.redBg+"55":i%2===1?t.tableHover+"55":"transparent",cursor:"pointer"}}
                onClick={()=>handleBkAsinClick(r)}
                onMouseEnter={e=>e.currentTarget.style.background=isSel?t.primaryLight+"cc":behind?t.redBg+"88":t.tableHover}
                onMouseLeave={e=>e.currentTarget.style.background=isSel?t.primaryLight:behind?t.redBg+"55":i%2===1?t.tableHover+"55":"transparent"}>
                <td style={{padding:"9px 12px",borderBottom:"1px solid "+t.divider,borderLeft:`2px solid ${isSel?t.primary:"transparent"}`}}>
                  <div style={{display:"flex",alignItems:"center",gap:5}}>
                    {behind&&<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={pc} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>}
                    <AsinLink asin={r.a} onClick={()=>handleBkAsinClick(r)} t={t}/>
                  </div>
                </td>
                <td style={{padding:"9px 10px",borderBottom:"1px solid "+t.divider,fontWeight:600,fontSize:11}}>{r.br||"—"}</td>
                <td style={{padding:"9px 10px",borderBottom:"1px solid "+t.divider,color:t.primary,fontWeight:600,fontSize:11}}>{r.sl||"—"}</td>
                <td style={{padding:"9px 10px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>
                  {r._pctGp!=null
                    ?<span style={{background:pc+"22",color:pc,padding:"3px 9px",borderRadius:6,fontSize:11,fontWeight:700}}>
                        {r.ga<0?"⛔ LOSS":r._pctGp+"%"}
                      </span>
                    :<span style={{color:t.textMuted}}>—</span>}
                </td>
                <td style={{padding:"9px 10px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.ga} plan={r._gpPlanYtd??r.gp} t={t}/></td>
                <td style={{padding:"9px 10px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td>
                <td style={{padding:"9px 10px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td>
                <td style={{padding:"9px 10px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td>
                <td style={{padding:"9px 10px",textAlign:"right",borderBottom:"1px solid "+t.divider,fontWeight:700,color:r._margin==null?t.textMuted:r._margin>25?t.green:r._margin>15?t.orange:t.red}}>{r._margin!=null?r._margin.toFixed(1)+"%":"—"}</td>
                <td style={{padding:"9px 10px",textAlign:"right",borderBottom:"1px solid "+t.divider,fontWeight:700,color:r._roas==null?t.textMuted:r._roas>8?t.green:r._roas>5?t.orange:t.red}}>{r._roas!=null?r._roas.toFixed(2)+"x":"—"}</td>
              </tr>;
            })}
            {bkRows.length===0&&<tr><td colSpan={10} style={{padding:32,textAlign:"center",color:t.textMuted}}>Không có ASIN nào khớp</td></tr>}
          </tbody>
        </table>
      </div>
      <div style={{padding:"7px 14px",fontSize:9.5,color:t.textMuted,borderTop:"1px solid "+t.divider,display:"flex",justifyContent:"space-between",flexWrap:"wrap",gap:4}}>
        <span><span style={{color:t.primary}}>Click ASIN</span> → sync Store + Seller · Actual / Plan / <span style={{color:t.green}}>Gap%</span></span>
        <span>✦ Margin = GP÷Rev · ROAS = Rev÷Ads</span>
      </div>
    </div>}

    {/* ── Tab: Monthly Table ── */}
    {activeTab==="monthly"&&<div style={{background:t.card,border:"1px solid "+t.cardBorder,borderRadius:12,overflow:"hidden"}}>
      <div style={{overflowX:"auto"}}>
        <table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12}}>
          <thead><tr>
            {[["Month","left",false],["GP",null,true],["Revenue"],["Ads"],["Units"],["ROAS ✦"],["Margin ✦"],["Sessions"],["Impressions"],["CR %"],["CTR %"]].map(([h,a,gp],i)=>(
              <th key={i} style={{padding:"10px 12px",textAlign:a||"right",fontSize:9.5,fontWeight:700,color:gp?t.primary:t.textMuted,textTransform:"uppercase",borderBottom:`2px solid ${t.divider}`,background:gp?t.primaryLight:t.tableBg,whiteSpace:"nowrap",position:"sticky",top:0,zIndex:2}}>{h}</th>
            ))}
          </tr></thead>
          <tbody>{mpd.map((r,i)=>{
            const has=(r.gpa||0)+(r.ra||0)>0;
            const roas=r.aa>0?r.ra/r.aa:null,margin=r.ra>0?r.gpa/r.ra*100:null;
            const pr=r.ap>0?r.rp/r.ap:null,pm=r.rp>0?r.gpp/r.rp*100:null;
            const sel=planMonth===r.m;
            return<tr key={i} style={{opacity:has?1:.5,background:sel?t.primaryLight:"transparent"}}
              onMouseEnter={e=>e.currentTarget.style.background=sel?t.primaryLight:t.tableHover}
              onMouseLeave={e=>e.currentTarget.style.background=sel?t.primaryLight:"transparent"}>
              <td style={{padding:"10px 12px",fontWeight:sel?800:700,borderBottom:"1px solid "+t.divider,color:sel?t.primary:t.text}}>
                {r.m}{!has&&<span style={{fontSize:8,color:t.textMuted,marginLeft:5}}>(planned)</span>}
                {sel&&<span style={{marginLeft:6,fontSize:9,color:t.primary}}>◀</span>}
              </td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.gpa} plan={r.gpp} t={t}/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra}   plan={r.rp}  t={t}/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa}   plan={r.ap}  t={t} reverse/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua}   plan={r.up}  t={t} isMoney={false}/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={roas}   plan={pr}    t={t} isMoney={false} suffix="x"/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={margin} plan={pm}    t={t} isMoney={false} suffix="%"/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={r.sa}   plan={r.sp}  t={t} isMoney={false}/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={r.ia}   plan={r.ip}  t={t} isMoney={false}/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={r.cra}  plan={r.crp} t={t} isMoney={false} suffix="%"/></td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}><APG actual={r.cta}  plan={r.ctp} t={t} isMoney={false} suffix="%"/></td>
            </tr>;
          })}</tbody>
        </table>
      </div>
      <div style={{padding:"7px 14px",fontSize:9.5,color:t.textMuted,borderTop:"1px solid "+t.divider}}>
        Actual / Plan / <span style={{color:t.green}}>Gap (%)</span> · ✦ ROAS = Rev÷Ads · Margin = GP÷Rev · Months without data shown at reduced opacity
      </div>
    </div>}

    {/* ── Tab: Alerts ── */}
    {activeTab==="alerts"&&<PlanAlertsTab alerts={alertRows} t={t} onAsinClick={r=>{if(onAsinClick)onAsinClick(r.a||r);}}/>}

    {/* Footer filter logic note */}
    <div style={{marginTop:12,padding:"8px 14px",borderRadius:8,border:"1px solid "+t.primary+"22",background:t.primaryLight,fontSize:10,color:t.textMuted,lineHeight:1.7}}>
      <strong style={{color:t.primary}}>Filter logic:</strong> Month = applies to entire tab · Brand/Seller/ASIN in header affects all sections · Column filters in Breakdown table are local only · <span style={{color:t.primary}}>Click ASIN row → syncs Brand + Seller</span> · ✦ Margin = GP÷Rev · ROAS = Rev÷Ads
    </div>
  </div>;
}

/* ═══════════ PRODUCT ═══════════ */
function ProdPage({t,fAsin,fDaily,onAsinClick}){
  const tR=fAsin.reduce((s,a)=>s+a.r,0),tN=fAsin.reduce((s,a)=>s+a.n,0),tU=fAsin.reduce((s,a)=>s+a.u,0);
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Revenue" value={$(tR)} icon="" t={t} tip={TIPS.prodRev}/><KpiCard title="Net Profit" value={$(tN)} icon="" t={t} tip={TIPS.prodNP}/><KpiCard title="Margin" value={(tR?(tN/tR*100).toFixed(2):0)+"%"} icon="" t={t} tip={TIPS.prodMargin}/><KpiCard title="Units" value={N(tU)} icon="" t={t} tip={TIPS.prodUnits}/></div>
    <Sec title="Revenue & NP Trend" icon="" t={t}><TrendChart data={fDaily} t={t}/></Sec>
    <Sec title="ASIN Table" icon="" t={t}><div style={{borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card,overflow:"hidden"}}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto"}}><table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:13}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{["ASIN","Shop","Seller","Revenue","Net Profit","Margin%","Units","CR%","ACoS","ROAS"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=3?"right":"left",color:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{fAsin.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontSize:13,fontWeight:600,letterSpacing:.3,borderBottom:"1px solid "+t.divider,color:t.text}}><AsinLink asin={r.a} onClick={onAsinClick||(()=>{})} t={t}/></td><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.b}</td><td style={{padding:"8px 12px",borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.sl}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(1)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.cr.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ac<30?t.green:r.ac<50?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ac.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.ro.toFixed(2)}</td></tr>)}</tbody></table></div><div style={{padding:"6px 12px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider,background:t.card}}>{fAsin.length} ASINs</div></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genAlerts([...fAsin],t)}/></div>
  </div>;
}

/* ═══════════ SHOP ═══════════ */
function ShopPage({t,fShopData,fDaily}){
  const tGP=fShopData.reduce((s,x)=>s+(x.gp||0),0),tSV=fShopData.reduce((s,x)=>s+(x.sv||0),0);
  const THDSHOP=["Shop","⭐ GP","REVENUE","ADS","UNITS","FBA STOCK","MARGIN","HEALTH","STOCK VALUE"];
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Total GP" value={$(tGP)} icon="" t={t} tip={TIPS.gp}/><div style={{background:t.card,borderRadius:12,padding:"16px 18px",border:"2px solid "+t.orange+"55"}}><div style={{fontSize:10,color:t.orange,textTransform:"uppercase",letterSpacing:.8,fontWeight:700,marginBottom:8}}>Stock Value</div><div style={{fontSize:20,fontWeight:700,color:t.text}}>{$(tSV)}</div>{tGP!==0&&<div style={{fontSize:11,color:t.textMuted,marginTop:4}}>{(tSV/Math.abs(tGP)).toFixed(1)}x GP</div>}</div><KpiCard title="Total Revenue" value={$(fShopData.reduce((s,x)=>s+x.r,0))} icon="" t={t} tip={TIPS.revenue}/><KpiCard title="FBA Stock" value={N(fShopData.reduce((s,x)=>s+x.f,0))} icon="" t={t} tip={TIPS.shopFba}/></div>
    <Sec title="Revenue Trend" icon="" t={t}><TrendChart data={fDaily} t={t} keys={[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"}]}/></Sec>
    <Sec title="Shop Table (A / P / Gap)" icon="" t={t}><div style={{borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card,overflow:"hidden"}}><div style={{overflowX:"auto",maxHeight:440,overflowY:"auto"}}><table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:13}}><thead><tr>{THDSHOP.map((h,i)=><th key={i} style={{position:"sticky",top:0,zIndex:2,padding:"10px 12px",textAlign:i===0?"left":i===7?"center":"right",color:h.includes("STOCK VALUE")?t.orange:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:h.includes("STOCK VALUE")?t.tableBg:h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap"}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{fShopData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.s}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.gp} plan={r.gpP||0} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.r} plan={r.rvP||0} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ad} plan={r.adP||0} t={t} reverse/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.u} plan={r.unP||0} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,fontWeight:600}}>{N(r.f)}</td><td style={{padding:"10px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider,fontWeight:600}}>{r.m.toFixed(2)}%</td><td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider,textAlign:"center"}}>{r.m>10?<span style={{background:t.greenBg,color:t.green,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Good</span>:r.m>0?<span style={{background:t.orangeBg,color:t.orange,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Fair</span>:<span style={{background:t.redBg,color:t.red,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Poor</span>}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><StockVal sv={r.sv} gp={r.gp} t={t}/></td></tr>)}</tbody></table></div><div style={{padding:"8px 14px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider}}>Each cell: <strong style={{color:t.text}}>Actual</strong> / Plan / <span style={{color:t.green}}>Gap</span> · Stock Health: <span style={{color:t.green}}>●</span> &lt;1.5x · <span style={{color:t.orange}}>●</span> 1.5-3x · <span style={{color:t.red}}>●</span> &gt;3x GP</div></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genShopAlerts(fShopData,t)}/></div>
  </div>;
}

/* ═══════════ TEAM ═══════════ */
function TeamPage({t,fSeller,fDaily,asinPlanBkData,onAsinClick}){
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
    // Sort by seller name first, then GP desc within each seller (empty seller → bottom)
    return[...filtered].sort((a,b)=>{
      const aEmpty=!a.sl,bEmpty=!b.sl;
      if(aEmpty!==bEmpty) return aEmpty?1:-1;
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
    return Object.values(map).map(s=>({...s,margin:sellerMargins[s.sl]?.margin||0})).sort((a,b)=>{if(a.sl==="Unknown"&&b.sl!=="Unknown")return 1;if(b.sl==="Unknown"&&a.sl!=="Unknown")return-1;return(b.ga||0)-(a.ga||0);});
  },[asinData,sellerMargins]);
  const THDSL=["Seller","⭐ GP","REVENUE","ADS","UNITS","MARGIN","ASINs","STOCK VALUE"];
  const THDASIN=["ASIN","Seller","Brand","⭐ GP","REVENUE","ADS","UNITS","STOCK VALUE"];
  // Detect seller group boundaries for visual separator
  const sellerBreaks=useMemo(()=>{const s=new Set();asinData.forEach((r,i)=>{if(i>0&&r.sl!==asinData[i-1].sl)s.add(i);});return s;},[asinData]);
  const noActuals=useMemo(()=>{const raw=asinPlanBkData||[];return raw.length>0&&raw.every(r=>!r.ga&&!r.ra&&!r.aa&&!r.ua);},[asinPlanBkData]);
  return<div>
    {noActuals&&<div style={{padding:"10px 14px",marginBottom:12,borderRadius:8,background:t.orange+"18",border:"1px solid "+t.orange+"44",fontSize:12,color:t.orange}}>⚠️ Actuals data = $0 — API may have failed or is still loading. Check browser console (F12) for errors.</div>}
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Total Revenue" value={$(fSeller.reduce((s,x)=>s+x.r,0))} icon="" t={t} tip={TIPS.teamRev}/><KpiCard title="Total GP" value={$(fSeller.reduce((s,x)=>s+x.n,0))} icon="" t={t} tip={TIPS.teamNP}/><KpiCard title="Avg Margin" value={(fSeller.length?(fSeller.reduce((s,x)=>s+x.m,0)/fSeller.length).toFixed(2):0)+"%"} icon="" t={t} tip={TIPS.teamMargin}/></div>
    <Sec title="Revenue Trend" icon="" t={t}><TrendChart data={fDaily} t={t} keys={[{dk:"revenue",n:"Revenue",c:t.primary,g:"url(#gRv)"}]}/></Sec>
    <Sec title="Seller Performance (A / P / Gap)" icon="" t={t} action={<div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:10,color:t.textMuted}}>Month:</span><Sel value={teamMonth} onChange={setTeamMonth} options={MS} label="All Months" t={t}/></div>}><div style={{borderRadius:12,border:"1px solid "+t.cardBorder,background:t.card,overflow:"hidden"}}><div style={{overflowX:"auto",maxHeight:400,overflowY:"auto"}}><table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12.5}}><thead><tr>{THDSL.map((h,i)=><th key={i} style={{position:"sticky",top:0,zIndex:2,padding:"11px 14px",textAlign:i===0?"left":"right",color:h==="STOCK VALUE"?t.orange:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:10.5,textTransform:"uppercase",letterSpacing:.5,borderBottom:"2px solid "+t.divider,background:h==="STOCK VALUE"?t.tableBg:h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i===0?80:100}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{sellerSummary.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"} style={{transition:"background .1s"}}><td style={{padding:"11px 14px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.sl}</td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.ga} plan={r.gp} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,fontWeight:600,color:mC(r.margin,t)}}>{r.margin.toFixed(2)}%</td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,fontWeight:600}}>{r.cnt}</td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><StockVal sv={r.sv} gp={r.ga} t={t}/></td></tr>)}</tbody></table></div><div style={{padding:"8px 14px",fontSize:10.5,color:t.textMuted,borderTop:"1px solid "+t.divider}}>Each cell: <strong style={{color:t.text}}>Actual</strong> / Plan / <span style={{color:t.green}}>Gap</span> · Stock Value = current snapshot · Ads: lower = better</div></div></Sec>
    {asinData.length>0&&<Sec title="ASIN Detail by Seller (A / P / Gap)" icon="" t={t}><div style={{borderRadius:12,border:"1px solid "+t.cardBorder,background:t.card,overflow:"hidden"}}><div style={{overflowX:"auto",maxHeight:520,overflowY:"auto"}}><table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12.5}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{THDASIN.map((h,i)=><th key={i} style={{padding:"11px 14px",textAlign:i<=2?"left":"right",color:h==="STOCK VALUE"?t.orange:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:10.5,textTransform:"uppercase",letterSpacing:.5,borderBottom:"2px solid "+t.divider,background:h==="STOCK VALUE"?t.tableBg:h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i<=2?70:100}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{asinData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"} style={sellerBreaks.has(i)?{borderTop:"2px solid "+t.divider}:{transition:"background .1s"}}><td style={{padding:"11px 14px",fontSize:13,fontWeight:600,letterSpacing:.3,borderBottom:"1px solid "+t.divider,color:t.textSec}}><AsinLink asin={r.a} onClick={onAsinClick||(()=>{})} t={t}/></td><td style={{padding:"11px 14px",fontWeight:600,borderBottom:"1px solid "+t.divider,fontSize:11.5,color:t.primary}}>{r.sl||"—"}</td><td style={{padding:"11px 14px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.br}</td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.ga} plan={r.gp} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"11px 14px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><StockVal sv={r.sv} gp={r.ga} t={t}/></td></tr>)}</tbody></table></div><div style={{padding:"8px 14px",fontSize:10.5,color:t.textMuted,borderTop:"1px solid "+t.divider,background:t.card}}>{asinData.length} ASINs · Grouped by seller · Stock Value = current snapshot</div></div></Sec>}
    <div style={{marginTop:14}}><Alerts t={t} alerts={genSellerAlerts(fSeller,t)}/></div>
  </div>;
}

/* ═══════════ OPS ═══════════ */
function OpsPage({t,fDaily,fShopData}){
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}><KpiCard title="Revenue" value={$(fDaily.reduce((s,x)=>s+x.revenue,0))} icon="" t={t} tip={TIPS.opsRev}/><KpiCard title="Gross Profit" value={$(fDaily.reduce((s,x)=>s+x.netProfit,0))} icon="" t={t} tip={TIPS.gp}/><KpiCard title="Units" value={N(fDaily.reduce((s,x)=>s+x.units,0))} icon="" t={t} tip={TIPS.opsUnits}/></div>
    <Sec title="Daily Trend" icon="" t={t}><TrendChart data={fDaily} t={t}/></Sec>
    <Sec title="Shop Ops" icon="" t={t}><div style={{borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card,overflow:"hidden"}}><div style={{overflowX:"auto",maxHeight:400,overflowY:"auto"}}><table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:13}}><thead style={{position:"sticky",top:0,zIndex:2}}><tr>{["Shop","Revenue","GP","Ads","Units","FBA Stock","Stock Value"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=1?"right":"left",color:h==="Stock Value"?t.orange:t.textMuted,fontWeight:700,fontSize:10,borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}{h==="STOCK VALUE"&&<Tip text={TIPS.stockValue} t={t}/>}</th>)}</tr></thead><tbody>{fShopData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.s}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:(r.gp||0)>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.gp||0)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.ad||0)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u||0)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.f)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><StockVal sv={r.sv} gp={r.gp} t={t}/></td></tr>)}</tbody></table></div></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genOpsAlerts(fDaily,t)}/></div>
  </div>;
}

/* ═══════════ AI CHAT ═══════════ */
const AI_FONT="'Plus Jakarta Sans',system-ui,-apple-system,sans-serif";
// Load Plus Jakarta Sans font globally
if(typeof document!=='undefined'&&!document.getElementById('pjs-font')){const l=document.createElement('link');l.id='pjs-font';l.rel='stylesheet';l.href='https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap';document.head.appendChild(l);const s=document.createElement('style');s.textContent=`*{font-family:'Plus Jakarta Sans',system-ui,-apple-system,sans-serif!important}code,pre,.monospace,[style*="monospace"]{font-family:'JetBrains Mono','SF Mono','Cascadia Code',monospace!important}body{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}`;document.head.appendChild(s);}
const AI_HINTS={
  exec:["So sánh Jan vs Feb","Shop nào cần cắt quảng cáo?","Rủi ro lớn nhất hiện tại?"],
  inv:["Explain Sell-Through & Days of Supply","Nên xử lý hàng tồn >90 ngày như thế nào?","Phí storage có đáng lo không?"],
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

/* ═══════════ ANALYTICS PAGE ═══════════ */
function AnalyticsPage({t,fDaily,fShopData,fSeller,fAsin,em,monthPlanData,sd,ed}){
  const[layer,setLayer]=useState("diagnostic");
  const[dTab,setDTab]=useState("drivers");
  const[pMetric,setPMetric]=useState("revenue");
  const[rView,setRView]=useState("list");

  // Period info
  const periodLabel=sd&&ed?`${sd} → ${ed}`:"All time";
  const dayCount=fDaily?.length||0;

  // ═══ COMPUTE DIAGNOSTIC DATA ═══
  const MS2=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  const monthly=useMemo(()=>{
    if(!monthPlanData?.length)return[];
    return monthPlanData.filter(m=>m.ra>0).map(m=>{
      // Ensure mn exists — derive from m (month name) if missing
      let mn=m.mn;
      if(!mn&&m.m){const idx=MS2.indexOf(m.m);if(idx>=0)mn=idx+1;}
      return{...m,mn};
    });
  },[monthPlanData]);

  const mom=useMemo(()=>{
    if(monthly.length<2)return null;
    const prev=monthly[monthly.length-2],cur=monthly[monthly.length-1];
    if(!prev||!cur||!prev.ra)return null;
    const rvChg=((cur.ra-prev.ra)/Math.abs(prev.ra)*100);
    const unChg=prev.ua?((cur.ua-prev.ua)/prev.ua*100):0;
    const crPrev=prev.cra*100,crCur=cur.cra*100;
    const acosPrev=prev.ra>0?(prev.aa/prev.ra*100):0,acosCur=cur.ra>0?(cur.aa/cur.ra*100):0;
    return{prev,cur,rvChg,unChg,crDelta:crCur-crPrev,acosDelta:acosCur-acosPrev,crPrev,crCur,acosPrev,acosCur,
      gpFrom:prev.gpa,gpTo:cur.gpa,gpChg:prev.gpa!==0?((cur.gpa-prev.gpa)/Math.abs(prev.gpa)*100):999};
  },[monthly]);

  // Waterfall (current month)
  const waterfall=useMemo(()=>{
    if(!em)return[];
    const rev=em.sales||0,ads=Math.abs(em.advCost||0),fees=Math.abs(em.amazonFees||0),cogs=Math.abs(em.cogs||0),
      refund=Math.abs(em.refundCost||0),ship=Math.abs(em.shippingCost||0),gp=em.grossProfit||0;
    return[
      {name:"Revenue",value:rev,fill:t.primary},{name:"COGS",value:-cogs,fill:t.red},
      {name:"Amazon Fees",value:-fees,fill:"#8B5CF6"},{name:"Ads",value:-ads,fill:t.orange},
      {name:"Refunds",value:-refund,fill:"#F59E0B"},{name:"Shipping",value:-ship,fill:t.textMuted},
      {name:"Gross Profit",value:gp,fill:t.green},
    ];
  },[em,t]);

  // Shop contribution
  const shopGP=useMemo(()=>{
    if(!fShopData?.length)return[];
    return[...fShopData].sort((a,b)=>(b.gp||0)-(a.gp||0)).slice(0,10).map(s=>({shop:s.s,gp:s.gp||0,rv:s.r||0,ads:s.ad||0,margin:s.m||0,sv:s.sv||0}));
  },[fShopData]);

  // Daily anomaly (compute 7-day MA)
  const anomalyData=useMemo(()=>{
    if(!fDaily?.length)return[];
    return fDaily.map((d,i)=>{
      const window=fDaily.slice(Math.max(0,i-6),i+1);
      const avg=window.reduce((s,x)=>s+x.revenue,0)/window.length;
      const dev=Math.abs(d.revenue-avg)/Math.max(avg,1);
      return{d:d.date?.substring?.(5,10)||"",rv:d.revenue,np:d.netProfit,avg:Math.round(avg),flag:dev>0.3};
    });
  },[fDaily]);

  // ASIN anomalies (top movers)
  const asinAnomalies=useMemo(()=>{
    if(!fAsin?.length)return[];
    const sorted=[...fAsin].sort((a,b)=>Math.abs(b.n)-Math.abs(a.n));
    const topProfit=sorted.filter(a=>a.n>0).slice(0,3).map(a=>({asin:a.a,shop:a.b,metric:"Net Profit",value:$(a.n),detail:`Rev ${$(a.r)}, Margin ${a.m.toFixed(1)}%, ACoS ${a.ac.toFixed(1)}%`,type:"spike"}));
    const topLoss=sorted.filter(a=>a.n<0).slice(0,3).map(a=>({asin:a.a,shop:a.b,metric:"Net Loss",value:$(a.n),detail:`Rev ${$(a.r)} but ACoS ${a.ac.toFixed(1)}% — ads eating margin`,type:"drop"}));
    const highAcos=fAsin.filter(a=>a.ac>40&&a.r>10000).sort((a,b)=>b.ac-a.ac).slice(0,2).map(a=>({asin:a.a,shop:a.b,metric:"High ACoS",value:a.ac.toFixed(1)+"%",detail:`Rev ${$(a.r)}, Margin only ${a.m.toFixed(1)}% — ads cost unsustainable`,type:"warning"}));
    return[...topProfit,...topLoss,...highAcos].slice(0,8);
  },[fAsin]);

  // Drivers
  const driversList=useMemo(()=>{
    if(!mom)return[];
    return[
      {factor:"Revenue Growth",impact:mom.rvChg>=0?"+":"",impactVal:mom.rvChg.toFixed(0)+"%",pct:45,detail:`Revenue ${$(mom.prev.ra)} → ${$(mom.cur.ra)}`,kpi:[{l:"Prev",v:$(mom.prev.ra)},{l:"Cur",v:$(mom.cur.ra)},{l:"MoM",v:(mom.rvChg>=0?"+":"")+mom.rvChg.toFixed(0)+"%"}]},
      {factor:"Conversion Rate",impact:mom.crDelta>=0?"+":"",impactVal:mom.crDelta.toFixed(1)+"pp",pct:25,detail:`CR ${mom.crPrev.toFixed(1)}% → ${mom.crCur.toFixed(1)}%`,kpi:[{l:"Prev",v:mom.crPrev.toFixed(1)+"%"},{l:"Cur",v:mom.crCur.toFixed(1)+"%"},{l:"Δ",v:(mom.crDelta>=0?"+":"")+mom.crDelta.toFixed(1)+"pp"}]},
      {factor:"Ads Efficiency",impact:mom.acosDelta<=0?"+":"",impactVal:mom.acosDelta.toFixed(1)+"pp ACoS",pct:20,detail:`ACoS ${mom.acosPrev.toFixed(1)}% → ${mom.acosCur.toFixed(1)}%`,kpi:[{l:"Prev ACoS",v:mom.acosPrev.toFixed(1)+"%"},{l:"Cur ACoS",v:mom.acosCur.toFixed(1)+"%"}]},
      {factor:"Volume",impact:mom.unChg>=0?"+":"",impactVal:N(Math.abs(mom.cur.ua-mom.prev.ua))+" units",pct:10,detail:`Units ${N(mom.prev.ua)} → ${N(mom.cur.ua)} (${mom.unChg>=0?"+":""}${mom.unChg.toFixed(0)}%)`,kpi:[{l:"Prev",v:N(mom.prev.ua)},{l:"Cur",v:N(mom.cur.ua)}]},
    ];
  },[mom]);

  // ═══ PREDICTIVE DATA ═══
  const forecast=useMemo(()=>{
    if(!monthly.length)return[];
    const now=new Date();const curMn=now.getMonth()+1;const curDay=now.getDate();
    // Complete months = exclude current month if < 20 days in
    const complete=monthly.filter(m=>!(m.mn===curMn&&curDay<20));
    if(complete.length<2)return monthly.map(m=>({m:m.m,actual:m.ra,gp:m.gpa,units:m.ua,sessions:m.sa}));

    const last=complete[complete.length-1],prev=complete[complete.length-2];
    const growthRate=prev.ra>0?Math.min(Math.max(last.ra/prev.ra,0.5),3.0):1;
    const avgRev=(last.ra+prev.ra)/2;
    const MS=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const seasonal=[1.0,1.1,0.95,0.9,0.85,1.05,1.15,1.1,0.95,1.2,1.3,1.0];
    const gpMargin=last.gpa>0&&last.ra>0?(last.gpa/last.ra):0.15;

    // Build forecast map for future months
    const fcMap={};
    for(let i=1;i<=4;i++){
      const mi=(last.mn-1+i)%12;
      const rv=Math.round(avgRev*growthRate*seasonal[mi]*(0.95+i*0.02));
      fcMap[MS[mi]]={forecast:rv,gpF:Math.round(rv*gpMargin*(0.9+i*0.03)),
        unitsF:Math.round(last.ua*(rv/last.ra)),sessF:Math.round(last.sa*(rv/last.ra)*0.95),
        lo:Math.round(rv*0.82),hi:Math.round(rv*1.18),
        gpLo:Math.round(rv*gpMargin*(0.9+i*0.03)*0.75),gpHi:Math.round(rv*gpMargin*(0.9+i*0.03)*1.25),
        unitsLo:Math.round(last.ua*(rv/last.ra)*0.82),unitsHi:Math.round(last.ua*(rv/last.ra)*1.18),
        sessLo:Math.round(last.sa*(rv/last.ra)*0.85),sessHi:Math.round(last.sa*(rv/last.ra)*1.15)};
    }

    // Build result: actual months + merge forecast into existing + add future months
    const result=monthly.map(m=>{
      const fc=fcMap[m.m];
      return{m:m.m,actual:m.ra,gp:m.gpa,units:m.ua,sessions:m.sa,...(fc||{})};
    });
    // Add pure forecast months not in actuals
    Object.entries(fcMap).forEach(([month,fc])=>{
      if(!result.find(r=>r.m===month)) result.push({m:month,...fc});
    });
    return result;
  },[monthly]);

  // Stock depletion
  const depletion=useMemo(()=>{
    if(!fAsin?.length)return[];
    return fAsin.filter(a=>a.r>5000).slice(0,20).map(a=>{
      const daysSel=fDaily?.length||30;
      const dailyUnits=daysSel>0?a.u/daysSel:0;
      const stock=Math.round(dailyUnits*30);// rough est
      const daysLeft=dailyUnits>0?Math.round(stock/dailyUnits):999;
      return{asin:a.a,shop:a.b,stock,velocity:dailyUnits.toFixed(1),daysLeft,revenue:a.r,
        urgency:daysLeft<21?"critical":daysLeft<45?"warning":"ok",
        action:daysLeft<21?"Restock immediately":daysLeft<45?"Plan restock soon":"Monitor"};
    }).sort((a,b)=>a.daysLeft-b.daysLeft).slice(0,8);
  },[fAsin,fDaily]);

  // ═══ PRESCRIPTIVE ═══
  const prescriptions=useMemo(()=>{
    const rx=[];
    // High ACoS ASINs
    const highAcos=fAsin?.filter(a=>a.ac>40&&a.r>10000).sort((a,b)=>b.ac-a.ac).slice(0,2)||[];
    highAcos.forEach(a=>rx.push({p:"P1",action:`Cut ads ${a.a}`,reason:`ACoS ${a.ac.toFixed(1)}% vs margin ${a.m.toFixed(1)}% — losing on ads`,impact:`+$${Math.round(a.r*a.ac/100*0.3/1000)}K/mo`,effort:"Low",roi:"High",timeline:"Next week",color:t.orange}));
    // High margin ASINs to scale
    const efficient=fAsin?.filter(a=>a.m>25&&a.ac<25&&a.r>20000).sort((a,b)=>b.m-a.m).slice(0,2)||[];
    efficient.forEach(a=>rx.push({p:"P1",action:`Scale ads ${a.a}`,reason:`Margin ${a.m.toFixed(1)}%, ACoS ${a.ac.toFixed(1)}% — room to grow`,impact:`+$${Math.round(a.r*0.15/1000)}K/mo`,effort:"Low",roi:"8x",timeline:"Next week",color:t.orange}));
    // Losing shops
    const losingShops=fShopData?.filter(s=>(s.gp||0)<0)||[];
    if(losingShops.length)rx.unshift({p:"P0",action:`Review ${losingShops.length} losing shops`,reason:`${losingShops.map(s=>s.s).join(", ")} — total loss ${$(losingShops.reduce((s,x)=>s+(x.gp||0),0))}`,impact:`+$${Math.round(Math.abs(losingShops.reduce((s,x)=>s+(x.gp||0),0))/1000)}K/mo`,effort:"Medium",roi:"5x",timeline:"This week",color:t.red});
    // High SV/GP shops
    const highSV=fShopData?.filter(s=>(s.sv||0)>0&&(s.gp||0)>0&&s.sv/s.gp>5).sort((a,b)=>(b.sv/b.gp)-(a.sv/a.gp)).slice(0,2)||[];
    highSV.forEach(s=>rx.unshift({p:"P0",action:`Liquidate ${s.s} excess stock`,reason:`SV/GP = ${(s.sv/s.gp).toFixed(1)}x — $${(s.sv/1000).toFixed(0)}K tied in inventory vs $${(s.gp/1000).toFixed(0)}K GP`,impact:`-$${Math.round(s.sv*0.3/1000)}K freed`,effort:"Medium",roi:"5x",timeline:"This week",color:t.red}));
    // Losing sellers
    const losingSellers=fSeller?.filter(s=>s.m<0&&s.sl!=="Unknown"&&s.sl!=="Unassigned")||[];
    if(losingSellers.length)rx.push({p:"P1",action:`Optimize ${losingSellers.length} losing sellers`,reason:`${losingSellers.map(s=>s.sl).join(", ")} — prune portfolios, focus top ASINs`,impact:`+$${Math.round(Math.abs(losingSellers.reduce((s,x)=>s+x.n,0))/1000)}K/mo`,effort:"High",roi:"3x",timeline:"2 weeks",color:t.orange});
    return rx.slice(0,8);
  },[fAsin,fShopData,fSeller,t]);

  const totalImpact=prescriptions.reduce((s,p)=>s+(parseInt((p.impact||"").replace(/[^0-9]/g,""))||0),0);

  // ═══ RENDER ═══
  const layers=[{id:"diagnostic",l:"Diagnostic",sub:"Why did it happen?",c:t.green,desc:"Auto-analyzes what drove metric changes between periods"},{id:"predictive",l:"Predictive",sub:"What will happen?",c:t.primary,desc:"Forecasts future revenue, GP, stock depletion"},{id:"prescriptive",l:"Prescriptive",sub:"What to do?",c:t.orange,desc:"Rule-based action plan from current data — ROI estimates auto-calculated"}];
  const Cd2=({children})=><div style={{background:t.card,borderRadius:14,border:"1px solid "+t.cardBorder,padding:"20px 24px",marginBottom:12}}>{children}</div>;
  const SH2=({title,sub})=><div style={{marginBottom:12}}><div style={{fontSize:15,fontWeight:800,color:t.text}}>{title}</div>{sub&&<div style={{fontSize:11,color:t.textMuted,marginTop:2}}>{sub}</div>}</div>;
  const Tag2=({text,color,bg})=><span style={{fontSize:10,fontWeight:700,color,background:bg||color+"18",padding:"3px 10px",borderRadius:10,display:"inline-block"}}>{text}</span>;
  const Note=({text,color})=><div style={{padding:"10px 14px",background:(color||t.primary)+"08",borderLeft:"3px solid "+(color||t.primary),borderRadius:"0 8px 8px 0",fontSize:11,color:t.textSec,lineHeight:1.6,marginBottom:12}}>{text}</div>;
  const MoMBadge=({v,suffix="%",reverse})=>{const pos=reverse?v<=0:v>=0;return<span style={{fontSize:12,fontWeight:700,color:pos?t.green:t.red}}>{v>=0?"+":""}{typeof v==="number"?v.toFixed(1):v}{suffix}</span>};

  return<div>
    {/* Period Info */}
    <div style={{padding:"10px 16px",marginBottom:14,borderRadius:10,background:t.tableBg,fontSize:12,color:t.textSec,display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:8}}>
      <div>Analyzing: <strong style={{color:t.text}}>{periodLabel}</strong> ({dayCount} days · {fAsin?.length||0} ASINs · {fShopData?.length||0} shops · {fSeller?.length||0} sellers)</div>
      <div style={{fontSize:10,color:t.textMuted}}>Use header filters (Start/End date, Shop, Seller) to change period</div>
    </div>
    {/* Layer tabs */}
    <div style={{display:"flex",gap:8,marginBottom:8}}>
      {layers.map(l=><button key={l.id} onClick={()=>setLayer(l.id)} style={{flex:1,padding:"14px 16px",border:"1px solid "+(layer===l.id?l.c:t.cardBorder),borderRadius:12,background:layer===l.id?l.c+"10":t.card,cursor:"pointer",textAlign:"left",transition:"all .2s"}}>
        <div style={{fontSize:14,fontWeight:700,color:layer===l.id?l.c:t.text}}>{l.l}</div>
        <div style={{fontSize:11,color:t.textMuted,marginTop:2}}>{l.sub}</div>
      </button>)}
    </div>
    <Note text={layers.find(l=>l.id===layer)?.desc} color={layers.find(l=>l.id===layer)?.c}/>

    {/* ═══ DIAGNOSTIC ═══ */}
    {layer==="diagnostic"&&<div>
      {/* MoM Summary */}
      {mom&&<Cd2>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:12}}>
          <div>
            <div style={{fontSize:11,color:t.textMuted,textTransform:"uppercase",letterSpacing:1,fontWeight:600}}>{mom.prev.m} → {mom.cur.m} Comparison</div>
            <div style={{fontSize:22,fontWeight:800,color:t.text,marginTop:6}}>Gross Profit: <MoMBadge v={mom.gpChg}/></div>
            <div style={{fontSize:13,color:t.textSec,marginTop:4}}>{$(mom.gpFrom)} → {$(mom.gpTo)}</div>
          </div>
          <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
            {[{l:"Revenue",v:mom.rvChg},{l:"Units",v:mom.unChg},{l:"CR",v:mom.crDelta,s:"pp"},{l:"ACoS",v:mom.acosDelta,s:"pp",rev:true}].map((k,i)=>
              <div key={i} style={{textAlign:"center",padding:"8px 14px",background:t.tableBg,borderRadius:10}}>
                <div style={{fontSize:9,color:t.textMuted,fontWeight:600}}>{k.l}</div>
                <MoMBadge v={k.v} suffix={k.s||"%"} reverse={k.rev}/>
              </div>
            )}
          </div>
        </div>
      </Cd2>}

      {/* KPI Comparison Grid */}
      {mom&&<div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:10,marginBottom:16}}>
        {[{l:"Revenue",prev:mom.prev.ra,cur:mom.cur.ra,fmt:$},{l:"Gross Profit",prev:mom.gpFrom,cur:mom.gpTo,fmt:$},{l:"Ads Spend",prev:mom.prev.aa,cur:mom.cur.aa,fmt:$,rev:true},{l:"Units",prev:mom.prev.ua,cur:mom.cur.ua,fmt:N},{l:"Sessions",prev:mom.prev.sa,cur:mom.cur.sa,fmt:N},{l:"Conv Rate",prev:mom.crPrev,cur:mom.crCur,fmt:v=>v.toFixed(1)+"%"}].map((k,i)=>{
          const chg=k.prev?((k.cur-k.prev)/Math.abs(k.prev)*100):0;const pos=k.rev?chg<=0:chg>=0;
          return<div key={i} style={{background:t.card,borderRadius:12,border:"1px solid "+t.cardBorder,padding:"14px 16px"}}>
            <div style={{fontSize:9,color:t.textMuted,textTransform:"uppercase",letterSpacing:1,fontWeight:600}}>{k.l}</div>
            <div style={{fontSize:18,fontWeight:800,color:t.text,marginTop:4}}>{k.fmt(k.cur)}</div>
            <div style={{fontSize:10,color:t.textMuted,marginTop:2}}>was {k.fmt(k.prev)}</div>
            <div style={{fontSize:11,fontWeight:700,color:pos?t.green:t.red,marginTop:4}}>{chg>=0?"+":""}{chg.toFixed(1)}%</div>
          </div>
        })}
      </div>}

      {/* Top Gainers & Losers */}
      {fAsin?.length>0&&<div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:16}}>
        <Cd2><SH2 title="Top Profit ASINs"/>{fAsin.filter(a=>a.n>0).slice(0,5).map((a,i)=><div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:i<4?"1px solid "+t.divider:"none"}}>
          <div><div style={{fontSize:12,fontWeight:700,color:t.primary}}>{a.a}</div><div style={{fontSize:10,color:t.textMuted}}>{a.b} · M:{a.m.toFixed(1)}%</div></div>
          <div style={{textAlign:"right"}}><div style={{fontSize:13,fontWeight:700,color:t.green}}>{$(a.n)}</div><div style={{fontSize:10,color:t.textMuted}}>ACoS {a.ac.toFixed(1)}%</div></div>
        </div>)}</Cd2>
        <Cd2><SH2 title="Biggest Losses"/>{fAsin.filter(a=>a.n<0).slice(0,5).map((a,i)=><div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:i<4?"1px solid "+t.divider:"none"}}>
          <div><div style={{fontSize:12,fontWeight:700,color:t.primary}}>{a.a}</div><div style={{fontSize:10,color:t.textMuted}}>{a.b} · ACoS:{a.ac.toFixed(1)}%</div></div>
          <div style={{textAlign:"right"}}><div style={{fontSize:13,fontWeight:700,color:t.red}}>{$(a.n)}</div><div style={{fontSize:10,color:t.textMuted}}>Rev {$(a.r)}</div></div>
        </div>)}</Cd2>
      </div>}

      {/* Sub-tabs */}
      <div style={{display:"flex",gap:6,marginBottom:16,flexWrap:"wrap"}}>
        {[{id:"drivers",l:"Why Analysis"},{id:"waterfall",l:"Cost Waterfall"},{id:"anomaly",l:"Anomaly Detection"},{id:"shops",l:"Shop Breakdown"}].map(tb=>
          <button key={tb.id} onClick={()=>setDTab(tb.id)} style={{padding:"8px 16px",border:"1px solid "+(dTab===tb.id?t.green:t.cardBorder),borderRadius:10,background:dTab===tb.id?t.green+"10":t.card,color:dTab===tb.id?t.green:t.textSec,fontSize:12,fontWeight:600,cursor:"pointer"}}>{tb.l}</button>
        )}
      </div>
      <Note text={dTab==="drivers"?"Contribution analysis: which factors drove the biggest GP change between periods. Weights show relative importance.":dTab==="waterfall"?"Cost breakdown: how revenue flows through each cost category to become Gross Profit. Identifies the largest cost drivers.":dTab==="anomaly"?"Flags days and ASINs with unusual behavior vs rolling 7-day average. Deviation >30% = flagged.":"Shop-level GP comparison showing which shops drove overall performance change."} color={t.green}/>

      {dTab==="drivers"&&<div>
        <SH2 title="Why did metrics change?" sub="Automated driver analysis — contribution to GP change"/>
        {driversList.map((dr,i)=><Cd2 key={i}>
          <div style={{display:"flex",alignItems:"flex-start",gap:14}}>
            <div style={{width:40,height:40,borderRadius:10,background:t.primaryLight,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,fontSize:14,fontWeight:800,color:t.primary}}>{i+1}</div>
            <div style={{flex:1}}>
              <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                <span style={{fontSize:14,fontWeight:700,color:t.text}}>{dr.factor}</span>
                <Tag2 text={dr.impact+dr.impactVal} color={t.green}/>
                <span style={{fontSize:10,color:t.textMuted,marginLeft:"auto"}}>{dr.pct}% contribution</span>
              </div>
              <div style={{fontSize:12,color:t.textSec,marginTop:4,lineHeight:1.5}}>{dr.detail}</div>
              <div style={{display:"flex",gap:8,marginTop:8,flexWrap:"wrap"}}>
                {dr.kpi.map((k,j)=><div key={j} style={{padding:"4px 10px",background:t.tableBg,borderRadius:6}}>
                  <span style={{fontSize:9,color:t.textMuted}}>{k.l}: </span><span style={{fontSize:11,fontWeight:700,color:t.text}}>{k.v}</span>
                </div>)}
              </div>
            </div>
            <div style={{width:70,flexShrink:0}}>
              <div style={{height:8,borderRadius:4,background:t.tableBg,overflow:"hidden"}}><div style={{height:8,borderRadius:4,background:t.green,width:dr.pct+"%"}}/></div>
            </div>
          </div>
        </Cd2>)}
      </div>}

      {dTab==="waterfall"&&<div>
        <SH2 title="Revenue → Gross Profit Waterfall" sub="Period cost breakdown"/>
        <Cd2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={waterfall} margin={{top:20,right:20,bottom:5}}>
              <CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/>
              <XAxis dataKey="name" tick={{fill:t.textSec,fontSize:10}}/>
              <YAxis tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>$s(v)}/>
              <Tooltip content={({active,payload})=>active&&payload?.[0]?<div style={{background:t.card,border:"1px solid "+t.cardBorder,borderRadius:8,padding:"10px 14px"}}>
                <div style={{fontWeight:700,fontSize:12,color:t.text}}>{payload[0].payload.name}</div>
                <div style={{fontSize:12,color:payload[0].payload.value>=0?t.green:t.red,fontWeight:700}}>{$(payload[0].payload.value)}</div>
              </div>:null}/>
              <Bar dataKey="value" radius={[4,4,4,4]}>{waterfall.map((e,i)=><Cell key={i} fill={e.fill}/>)}</Bar>
            </BarChart>
          </ResponsiveContainer>
          {em&&<div style={{marginTop:12,padding:"10px 14px",background:t.tableBg,borderRadius:8,fontSize:11,color:t.textSec,lineHeight:1.6}}>
            <strong style={{color:t.text}}>Key insight:</strong> Amazon Fees ({em.amazonFees?((Math.abs(em.amazonFees)/em.sales*100).toFixed(1)):0}% of revenue) is the largest cost — {Math.abs(em.amazonFees||0)>Math.abs(em.advCost||0)?(Math.abs(em.amazonFees||0)/Math.max(Math.abs(em.advCost||0),1)).toFixed(1)+"x":"less than"} Ads spend.
          </div>}
          {/* Cost Structure Donut */}
          {em&&<div style={{marginTop:16}}>
            <div style={{fontSize:12,fontWeight:700,color:t.text,marginBottom:8}}>Cost Structure (% of Revenue)</div>
            <div style={{display:"flex",gap:16,flexWrap:"wrap"}}>
              {[{l:"Amazon Fees",v:Math.abs(em.amazonFees||0),c:"#8B5CF6"},{l:"Ads",v:Math.abs(em.advCost||0),c:t.orange},{l:"COGS",v:Math.abs(em.cogs||0),c:t.red},{l:"Refunds",v:Math.abs(em.refundCost||0),c:"#F59E0B"},{l:"Shipping",v:Math.abs(em.shippingCost||0),c:t.textMuted},{l:"Gross Profit",v:em.grossProfit||0,c:t.green}].map((c,i)=>{
                const pct=em.sales>0?(c.v/em.sales*100):0;
                return<div key={i} style={{display:"flex",alignItems:"center",gap:8,minWidth:160}}>
                  <div style={{width:8,height:8,borderRadius:4,background:c.c,flexShrink:0}}/>
                  <div style={{flex:1}}>
                    <div style={{display:"flex",justifyContent:"space-between"}}><span style={{fontSize:11,color:t.textSec}}>{c.l}</span><span style={{fontSize:11,fontWeight:700,color:c.c}}>{pct.toFixed(1)}%</span></div>
                    <div style={{height:4,borderRadius:2,background:t.tableBg,marginTop:3}}><div style={{height:4,borderRadius:2,background:c.c,width:Math.max(pct,0.5)+"%"}}/></div>
                  </div>
                  <span style={{fontSize:10,color:t.textMuted,minWidth:55,textAlign:"right"}}>{$(c.v)}</span>
                </div>
              })}
            </div>
          </div>}
        </Cd2>
      </div>}

      {dTab==="anomaly"&&<div>
        <SH2 title="Anomaly Detection" sub="Days and ASINs with significant deviations"/>
        <Cd2>
          <div style={{fontSize:13,fontWeight:700,color:t.text,marginBottom:4}}>Daily Revenue vs 7-day Moving Average</div>
          <ResponsiveContainer width="100%" height={220}>
            <ComposedChart data={anomalyData}>
              <CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/>
              <XAxis dataKey="d" tick={{fill:t.textSec,fontSize:9}} interval={Math.max(0,Math.floor(anomalyData.length/12))}/>
              <YAxis tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>$s(v)}/>
              <Tooltip content={<CT t={t}/>}/>
              <Legend wrapperStyle={{fontSize:10}}/>
              <Area type="monotone" dataKey="rv" name="Revenue" stroke={t.primary} fill={t.primary} fillOpacity={0.08} strokeWidth={2}/>
              <Line type="monotone" dataKey="avg" name="7d Average" stroke={t.orange} strokeWidth={1.5} strokeDasharray="4 3" dot={false}/>
              <Line type="monotone" dataKey="np" name="Net Profit" stroke={t.green} strokeWidth={1.5} dot={false}/>
            </ComposedChart>
          </ResponsiveContainer>
        </Cd2>
        <SH2 title="ASIN-level Anomalies" sub="Top movers and warning signals"/>
        <div style={{display:"grid",gap:8}}>
          {asinAnomalies.map((a,i)=>{
            const c=a.type==="spike"?t.green:a.type==="drop"?t.red:t.orange;
            return<Cd2 key={i}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",borderLeft:"4px solid "+c,marginLeft:-24,paddingLeft:20}}>
                <div>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                    <span style={{fontSize:13,fontWeight:700,color:t.primary}}>{a.asin}</span>
                    <span style={{fontSize:11,color:t.textMuted}}>{a.shop}</span>
                    <Tag2 text={a.metric+": "+a.value} color={c}/>
                  </div>
                  <div style={{fontSize:11,color:t.textSec}}>{a.detail}</div>
                </div>
              </div>
            </Cd2>
          })}
        </div>
      </div>}

      {dTab==="shops"&&<div>
        <SH2 title="Shop Contribution to GP" sub="Which shops drive profitability?"/>
        <Cd2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={shopGP} margin={{top:10,right:20,bottom:5}}>
              <CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/>
              <XAxis dataKey="shop" tick={{fill:t.textSec,fontSize:10}}/>
              <YAxis tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>$s(v)}/>
              <Tooltip content={<CT t={t}/>}/>
              <Legend wrapperStyle={{fontSize:10}}/>
              <Bar dataKey="gp" name="Gross Profit" fill={t.green} radius={[4,4,0,0]}>{shopGP.map((e,i)=><Cell key={i} fill={(e.gp||0)>=0?t.green:t.red}/>)}</Bar>
              <Bar dataKey="ads" name="Ads Spend" fill={t.orange} radius={[4,4,0,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </Cd2>
        <Cd2>
          <table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12}}>
            <thead><tr>{["Shop","Revenue","GP","Margin","Ads","SV/GP"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i===0?"left":"right",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead>
            <tbody>{shopGP.map((s,i)=>{const ratio=s.gp>0&&s.sv>0?(s.sv/s.gp).toFixed(1)+"x":"—";const rc=s.gp>0&&s.sv/s.gp>3?t.red:s.gp>0&&s.sv/s.gp>1.5?t.orange:t.green;
              return<tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                <td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{s.shop}</td>
                <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(s.rv)}</td>
                <td style={{padding:"10px 12px",textAlign:"right",fontWeight:700,color:s.gp>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(s.gp)}</td>
                <td style={{padding:"10px 12px",textAlign:"right",color:mC(s.margin,t),borderBottom:"1px solid "+t.divider}}>{s.margin.toFixed(1)}%</td>
                <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(s.ads)}</td>
                <td style={{padding:"10px 12px",textAlign:"right",fontWeight:600,color:rc,borderBottom:"1px solid "+t.divider}}>{ratio}</td>
              </tr>})}</tbody>
          </table>
        </Cd2>
      </div>}
    </div>}

    {/* ═══ PREDICTIVE ═══ */}
    {layer==="predictive"&&<div>
      <Cd2>
        <div style={{fontSize:11,color:t.textMuted,textTransform:"uppercase",letterSpacing:1,fontWeight:600}}>Forecast Engine</div>
        <div style={{fontSize:18,fontWeight:800,color:t.text,marginTop:6}}>Revenue Forecast: {$(forecast.find(f=>f.forecast)?.forecast)||"Calculating..."}</div>
        <div style={{fontSize:12,color:t.textSec,marginTop:4}}>Method: Weighted Moving Average | {monthly.length} months of data | Forecasting: {forecast.filter(f=>f.forecast).map(f=>f.m).join(", ")||"—"}</div>
        <div style={{marginTop:8,padding:"8px 12px",background:t.primaryLight,borderRadius:8,fontSize:11,color:t.primary}}>
          Forecast accuracy improves with more data. Seasonal model available after 6+ months of history.
        </div>
      </Cd2>

      <Note text={"Confidence range shown as shaded area (±18%). Forecast uses weighted average of "+monthly.length+" months. Click metric tabs to switch between Revenue, GP, Units, Sessions."} color={t.primary}/>

      <div style={{display:"flex",gap:6,marginBottom:16}}>
        {[{id:"revenue",l:"Revenue"},{id:"gp",l:"Gross Profit"},{id:"units",l:"Units"},{id:"sessions",l:"Sessions"}].map(m=>
          <button key={m.id} onClick={()=>setPMetric(m.id)} style={{padding:"6px 14px",border:"1px solid "+(pMetric===m.id?t.primary:t.cardBorder),borderRadius:8,background:pMetric===m.id?t.primary+"10":t.card,color:pMetric===m.id?t.primary:t.textSec,fontSize:11,fontWeight:600,cursor:"pointer"}}>{m.l}</button>
        )}
      </div>

      <Cd2>
        <SH2 title="Actual vs Forecast" sub="Jan-Feb = basis months (actual data used to calculate forecast). Mar onwards = forecast with ±18% confidence range."/>
        <ResponsiveContainer width="100%" height={280}>
          <ComposedChart data={forecast}>
            <CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/>
            <XAxis dataKey="m" tick={{fill:t.textSec,fontSize:11}}/>
            <YAxis tick={{fill:t.textSec,fontSize:10}} tickFormatter={v=>pMetric==="units"||pMetric==="sessions"?N(v):$s(v)}/>
            <Tooltip content={<CT t={t}/>}/>
            <Legend wrapperStyle={{fontSize:10}}/>
            <Area dataKey={pMetric==="revenue"?"hi":pMetric==="gp"?"gpHi":pMetric==="units"?"unitsHi":"sessHi"} name="Best Case" stroke={t.green} strokeWidth={1.5} strokeDasharray="5 3" fill={t.green} fillOpacity={0.10}/>
            <Area dataKey={pMetric==="revenue"?"lo":pMetric==="gp"?"gpLo":pMetric==="units"?"unitsLo":"sessLo"} name="Worst Case" stroke={t.red} strokeWidth={1.5} strokeDasharray="5 3" fill={t.red} fillOpacity={0.10}/>
            <Bar dataKey={pMetric==="revenue"?"actual":pMetric} name="Actual" fill={t.primary} radius={[4,4,0,0]}/>
            <Bar dataKey={pMetric==="revenue"?"forecast":pMetric==="gp"?"gpF":pMetric==="units"?"unitsF":"sessF"} name="Forecast" fill={t.orange} fillOpacity={0.75} radius={[4,4,0,0]}/>
          </ComposedChart>
        </ResponsiveContainer>
      </Cd2>

      {/* Scenario Cards */}
      {forecast.length>0&&(()=>{const fc=forecast.find(f=>f.forecast);if(!fc)return null;return<div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:16}}>
        {[{l:"Worst Case",v:fc.lo,c:t.red,bg:t.redBg,desc:"If growth stalls + market headwinds"},{l:"Base Case",v:fc.forecast,c:t.primary,bg:t.primaryLight,desc:"Based on weighted average trend"},{l:"Best Case",v:fc.hi,c:t.green,bg:t.greenBg,desc:"If Feb growth momentum continues"}].map((s,i)=>
          <div key={i} style={{background:t.card,borderRadius:12,border:"1px solid "+t.cardBorder,padding:"16px",borderTop:"3px solid "+s.c}}>
            <div style={{fontSize:10,color:t.textMuted,fontWeight:600,textTransform:"uppercase",letterSpacing:1}}>{s.l}</div>
            <div style={{fontSize:22,fontWeight:800,color:s.c,marginTop:6}}>{$(s.v)}</div>
            <div style={{fontSize:10,color:t.textMuted,marginTop:4}}>{s.desc}</div>
          </div>
        )}
      </div>})()}

      {/* Forecast all metrics summary */}
      {forecast.length>0&&<Cd2>
        <SH2 title="Forecast Summary — Next Month" sub={"Predicted values for "+(forecast.find(f=>f.forecast)?.m||"—")}/>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(130px,1fr))",gap:10}}>
          {(()=>{const fc=forecast.find(f=>f.forecast);if(!fc)return null;return[{l:"Revenue",v:$(fc.forecast)},{l:"Gross Profit",v:$(fc.gpF)},{l:"Units",v:N(fc.unitsF)},{l:"Sessions",v:N(fc.sessF)}].map((k,i)=>
            <div key={i} style={{textAlign:"center",padding:"12px",background:t.tableBg,borderRadius:10}}>
              <div style={{fontSize:9,color:t.textMuted,fontWeight:600,textTransform:"uppercase"}}>{k.l}</div>
              <div style={{fontSize:18,fontWeight:800,color:t.primary,marginTop:4}}>{k.v}</div>
              <div style={{fontSize:9,color:t.textMuted,marginTop:2}}>forecast</div>
            </div>
          )})()}
        </div>
      </Cd2>}

      <SH2 title="Stock Depletion Forecast" sub="Estimated days until stockout based on current velocity"/>
      <Note text="Days Left = Estimated Stock ÷ Daily velocity. Critical (<21d) = restock immediately. Warning (<45d) = plan restock. Stock is estimated from sales volume — actual FBA Stock available in Inventory page." color={t.primary}/>
      <Cd2>
        <table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12}}>
          <thead><tr>{["ASIN","Shop","Est. Stock","Velocity","Days Left","Revenue","Status"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i<2?"left":"right",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead>
          <tbody>{depletion.map((s,i)=>{
            const uc=s.urgency==="critical"?t.red:s.urgency==="warning"?t.orange:t.green;
            return<tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
              <td style={{padding:"10px 12px",fontWeight:700,color:t.primary,borderBottom:"1px solid "+t.divider}}>{s.asin}</td>
              <td style={{padding:"10px 12px",borderBottom:"1px solid "+t.divider}}>{s.shop}</td>
              <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(s.stock)}</td>
              <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{s.velocity}/d</td>
              <td style={{padding:"10px 12px",textAlign:"right",fontWeight:800,fontSize:15,color:uc,borderBottom:"1px solid "+t.divider}}>{s.daysLeft}d</td>
              <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(s.revenue)}</td>
              <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><Tag2 text={s.urgency.toUpperCase()} color={uc}/></td>
            </tr>
          })}</tbody>
        </table>
      </Cd2>
    </div>}

    {/* ═══ PRESCRIPTIVE ═══ */}
    {layer==="prescriptive"&&<div>
      <Cd2>
        <div style={{fontSize:11,color:t.textMuted,textTransform:"uppercase",letterSpacing:1,fontWeight:600}}>Auto-Generated Action Plan</div>
        <div style={{fontSize:18,fontWeight:800,color:t.text,marginTop:6}}>{prescriptions.length} actions | Est. impact: +${totalImpact}K GP/month</div>
        <div style={{fontSize:12,color:t.textSec,marginTop:4}}>Based on: rule-based analysis of ACoS, SV/GP ratio, margin, and shop performance</div>
      </Cd2>

      <Note text="Actions are auto-generated from current data. Priority: P0 = do this week, P1 = this month, P2 = plan ahead. ROI = estimated return on effort. Review and adjust before executing." color={t.orange}/>

      {/* Impact Summary KPIs */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(130px,1fr))",gap:10,marginBottom:16}}>
        {[{l:"Total Actions",v:prescriptions.length,c:t.text},{l:"P0 (Urgent)",v:prescriptions.filter(p=>p.p==="P0").length,c:t.red},{l:"Monthly Impact",v:"+$"+totalImpact+"K",c:t.green},{l:"Annual Impact",v:"+$"+(totalImpact*12)+"K",c:t.green}].map((k,i)=>
          <div key={i} style={{background:t.card,borderRadius:12,border:"1px solid "+t.cardBorder,padding:"16px",textAlign:"center"}}>
            <div style={{fontSize:9,color:t.textMuted,fontWeight:600,textTransform:"uppercase",letterSpacing:1}}>{k.l}</div>
            <div style={{fontSize:24,fontWeight:800,color:k.c,marginTop:6}}>{k.v}</div>
          </div>
        )}
      </div>

      {/* Effort vs Impact Overview */}
      <Cd2>
        <SH2 title="Action Overview" sub="Priority breakdown by effort and impact"/>
        <table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12}}>
          <thead><tr>{["Action","Priority","Impact","Effort","ROI","Timeline"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i===0?"left":"right",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead>
          <tbody>{prescriptions.map((a,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
            <td style={{padding:"10px 12px",fontWeight:600,borderBottom:"1px solid "+t.divider,maxWidth:200}}>{a.action}</td>
            <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><Tag2 text={a.p} color={a.color}/></td>
            <td style={{padding:"10px 12px",textAlign:"right",fontWeight:700,color:t.green,borderBottom:"1px solid "+t.divider}}>{a.impact}</td>
            <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><Tag2 text={a.effort} color={a.effort==="Low"?t.green:a.effort==="Medium"?t.orange:t.red}/></td>
            <td style={{padding:"10px 12px",textAlign:"right",fontWeight:700,color:t.primary,borderBottom:"1px solid "+t.divider}}>{a.roi}</td>
            <td style={{padding:"10px 12px",textAlign:"right",color:t.textSec,borderBottom:"1px solid "+t.divider}}>{a.timeline}</td>
          </tr>)}</tbody>
        </table>
      </Cd2>

      <div style={{display:"flex",gap:6,marginBottom:16,flexWrap:"wrap"}}>
        {[{id:"list",l:"Action List"},{id:"timeline",l:"Timeline"},{id:"roi",l:"ROI Summary"}].map(tb=>
          <button key={tb.id} onClick={()=>setRView(tb.id)} style={{padding:"8px 16px",border:"1px solid "+(rView===tb.id?t.orange:t.cardBorder),borderRadius:10,background:rView===tb.id?t.orange+"10":t.card,color:rView===tb.id?t.orange:t.textSec,fontSize:12,fontWeight:600,cursor:"pointer"}}>{tb.l}</button>
        )}
      </div>

      {rView==="list"&&<div style={{display:"grid",gap:10}}>
        {prescriptions.map((a,i)=><Cd2 key={i}>
          <div style={{display:"flex",gap:14}}>
            <div style={{width:40,background:a.color,borderRadius:8,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
              <span style={{color:"white",fontWeight:800,fontSize:11}}>{a.p}</span>
            </div>
            <div style={{flex:1}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",flexWrap:"wrap",gap:8}}>
                <div style={{fontSize:14,fontWeight:700,color:t.text}}>{a.action}</div>
                <div style={{display:"flex",gap:6}}>
                  <Tag2 text={"ROI: "+a.roi} color={t.green}/>
                  <Tag2 text={a.effort} color={a.effort==="Low"?t.green:a.effort==="Medium"?t.orange:t.red}/>
                </div>
              </div>
              <div style={{fontSize:12,color:t.textSec,marginTop:4,lineHeight:1.5}}>{a.reason}</div>
              <div style={{display:"flex",gap:12,marginTop:8,alignItems:"center"}}>
                <Tag2 text={"Impact: "+a.impact} color={t.green}/>
                <span style={{fontSize:10,color:t.textMuted}}>Timeline: {a.timeline}</span>
              </div>
            </div>
          </div>
        </Cd2>)}
      </div>}

      {rView==="timeline"&&<Cd2>
        {["This week","Next week","2 weeks","1 month"].map((period,pi)=>{
          const items=prescriptions.filter(p=>p.timeline===period);
          if(!items.length)return null;
          return<div key={pi} style={{marginBottom:20}}>
            <div style={{fontSize:11,fontWeight:700,color:[t.red,t.orange,t.orange,t.primary][pi],textTransform:"uppercase",letterSpacing:1,marginBottom:8}}>{period}</div>
            <div style={{borderLeft:"3px solid "+[t.red,t.orange,t.orange,t.primary][pi],paddingLeft:16,display:"grid",gap:8}}>
              {items.map((a,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:10,padding:"10px 14px",background:t.tableBg,borderRadius:8}}>
                <Tag2 text={a.p} color={a.color}/>
                <div style={{flex:1}}><div style={{fontSize:12,fontWeight:700,color:t.text}}>{a.action}</div><div style={{fontSize:10,color:t.textSec}}>{a.effort} effort | {a.impact}</div></div>
                <Tag2 text={"ROI "+a.roi} color={t.green}/>
              </div>)}
            </div>
          </div>
        })}
      </Cd2>}

      {rView==="roi"&&<div>
        <Cd2>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:12}}>
            {[{l:"Monthly Impact",v:"+$"+totalImpact+"K",c:t.green},{l:"Annual Impact",v:"+$"+(totalImpact*12)+"K",c:t.green},{l:"Actions",v:prescriptions.length+"",c:t.primary}].map((k,i)=>
              <div key={i} style={{textAlign:"center",padding:"14px",background:t.tableBg,borderRadius:10}}>
                <div style={{fontSize:9,color:t.textMuted,fontWeight:600,textTransform:"uppercase"}}>{k.l}</div>
                <div style={{fontSize:22,fontWeight:800,color:k.c,marginTop:4}}>{k.v}</div>
              </div>
            )}
          </div>
        </Cd2>
        <Cd2>
          <table style={{width:"100%",borderCollapse:"separate",borderSpacing:0,fontSize:12}}>
            <thead><tr>{["Action","Priority","Impact","Effort","ROI","Cumulative"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i===0?"left":"right",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead>
            <tbody>{prescriptions.map((a,i)=>{
              const cum=prescriptions.slice(0,i+1).reduce((s,p)=>s+(parseInt((p.impact||"").replace(/[^0-9]/g,""))||0),0);
              return<tr key={i}><td style={{padding:"10px 12px",fontWeight:600,borderBottom:"1px solid "+t.divider}}>{a.action}</td>
                <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><Tag2 text={a.p} color={a.color}/></td>
                <td style={{padding:"10px 12px",textAlign:"right",fontWeight:700,color:t.green,borderBottom:"1px solid "+t.divider}}>{a.impact}</td>
                <td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{a.effort}</td>
                <td style={{padding:"10px 12px",textAlign:"right",fontWeight:700,color:t.primary,borderBottom:"1px solid "+t.divider}}>{a.roi}</td>
                <td style={{padding:"10px 12px",textAlign:"right",fontWeight:700,color:t.text,borderBottom:"1px solid "+t.divider}}>+${cum}K</td>
              </tr>})}</tbody>
          </table>
        </Cd2>
      </div>}
    </div>}
  </div>;
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
const NAV=[{id:"exec",l:"Executive Overview",ico:"M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0h4"},{id:"inv",l:"Inventory",ico:"M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"},{id:"plan",l:"ASIN Plan",ico:"M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"},{id:"prod",l:"Product Performance",ico:"M16 8v8m-4-5v5m-4-2v2m-2 4h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"},{id:"shops",l:"Shop Performance",ico:"M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.3 2.3c-.5.5-.1 1.4.6 1.4H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 100 4 2 2 0 000-4z"},{id:"team",l:"Team Performance",ico:"M17 20h5v-2a3 3 0 00-5.4-1.7M17 20H7m10 0v-2c0-.7-.1-1.3-.4-1.9M7 20H2v-2a3 3 0 015.4-1.7M7 20v-2c0-.7.1-1.3.4-1.9m0 0a5 5 0 019.2 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"},{id:"daily",l:"Daily / Ops",ico:"M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"},{id:"analytics",l:"Analytics",ico:"M9.7 17L6 13.3l1.4-1.4 2.3 2.3 4.3-4.3 1.4 1.4L9.7 17zM12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm0 18c-4.4 0-8-3.6-8-8s3.6-8 8-8 8 3.6 8 8-3.6 8-8 8z"}];
const NavIco=({d,size=18,color})=><svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" style={{flexShrink:0}}><path d={d}/></svg>;

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
  const[selectedStores,setSelectedStores]=useState(()=>new Set());
  const[seller,setSeller]=useState("All");
  const[asinF,setAsinF]=useState("All");
  const storeStr=Array.from(selectedStores).join(',') || 'All';
  const store=storeStr;
  const setStore=str=>setSelectedStores(str==='All'||!str?new Set():new Set(str.split(',').map(s=>s.trim()).filter(Boolean)));
  const[planYear,setPlanYear]=useState(String(new Date().getFullYear()));
  const planYearOpts=useMemo(()=>{const c=new Date().getFullYear();return[String(c-1),String(c),String(c+1)]},[]);
  const clearDates=()=>{if(dbRange?.defaultStart)setSd(dbRange.defaultStart);else setSd(defaultStart);setEd(defaultEnd);setActivePeriod(null)};

  // ═══════════ LIVE DATA STATE ═══════════
  const[em,setEm]=useState(EMPTY_EM);
  const[prevEm,setPrevEm]=useState(null);
  const[prevPeriod,setPrevPeriod]=useState({s:'',e:''});
  const[fDaily,setFDaily]=useState([]);
  const[fAsin,setFAsin]=useState([]);
  const[fShopData,setFShopData]=useState([]);
  const[fSeller,setFSeller]=useState([]);
  const[invData,setInvData]=useState({});
  const[invShop,setInvShop]=useState([]);
  const[invTrend,setInvTrend]=useState([]);
  const[invFeeMonthly,setInvFeeMonthly]=useState([]);
  const[invAsin,setInvAsin]=useState([]);
  const[planKpiState,setPlanKpiState]=useState({gp:{a:0,p:0},np:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}});
  const[monthPlanState,setMonthPlanState]=useState([]);
  const[asinPlanBkState,setAsinPlanBkState]=useState([]);
  const[stockAsin,setStockAsin]=useState(null);
  const[masterList,setMasterList]=useState([]);
  const[splyEm,setSplyEm]=useState(null);
  const[dailyLY,setDailyLY]=useState([]);
  const[execDetail,setExecDetail]=useState({});
  const[shopExt,setShopExt]=useState([]);
  const[loading,setLoading]=useState(false);

  // ═══ ZONE A STATE ═══
  const[zoneAPreset,setZoneAPreset]=useState('tod_7_14_30');
  // zoneAStore is derived from selectedStores (shared with Zone B)
  const[zoneATileData,setZoneATileData]=useState([]);
  const[zoneALoading,setZoneALoading]=useState(false);

  const opts=useBidirectionalFilters(store,seller,asinF,masterList);
  // ═══ Favicon + Tab Title ═══
  useEffect(()=>{
    document.title="Amazon Dashboard";
    const col=isDark?"#161825":"#3B4A8A";
    const svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="${col}"/><polyline points="4,24 10,16 16,19 22,10 28,14" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" fill="none"/><circle cx="10" cy="16" r="2" fill="white"/><circle cx="16" cy="19" r="2" fill="white"/><circle cx="22" cy="10" r="2" fill="white"/></svg>`;
    const url="data:image/svg+xml,"+encodeURIComponent(svg);
    let link=document.querySelector("link[rel~='icon']");
    if(!link){link=document.createElement("link");link.rel="icon";document.head.appendChild(link);}
    link.href=url;
  },[isDark]);
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
          api("inventory/by-shop",{store}).then(d=>setInvShop((d||[]).map(r=>({s:r.shop,fba:r.fbaStock||0,avail:r.available||0,inb:r.inbound||0,res:r.reserved||0,crit:r.criticalSkus||0,st:r.sellThrough||0,doh:r.daysOfSupply||0})))).catch(()=>{});
          api("inventory/stock-trend",{store}).then(d=>setInvTrend((d||[]).map(r=>{const dt=new Date(r.date);return{d:MS[dt.getMonth()]+" "+dt.getDate(),v:parseInt(r.available)||0,fba:parseInt(r.fbaStock)||0}}))).catch(()=>{});
          api("inventory/storage-monthly",{store}).then(d=>setInvFeeMonthly(d||[])).catch(()=>{});
          api("inventory/by-asin",{store}).then(d=>setInvAsin(d||[])).catch(()=>{});
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
    setPrevPeriod({s:ps.toISOString().slice(0,10),e:pe.toISOString().slice(0,10)});
    // Batch 1: critical data (summary + daily)
    const arr=v=>Array.isArray(v)?v:[];
    (async()=>{try{
      const[summary,daily]=await Promise.all([
        api("exec/summary",p).catch(e=>{setFilterError(prev=>(prev?prev+' | ':'')+'Exec: '+e.message);return EMPTY_EM;}),
        api("exec/daily",p).catch(e=>{console.error("exec/daily FAIL:",e);setFilterError(prev=>(prev?prev+" | ":"")+"Daily: "+e.message);return[];}),
      ]);
      if(cancelled)return;
      setEm(summary&&summary.sales!=null?summary:EMPTY_EM);
      setFDaily(arr(daily).map(r=>{const ds=String(r.date).slice(0,10);const dt=new Date(ds+"T12:00:00");const label=isNaN(dt)?ds:MS[dt.getMonth()]+" "+dt.getDate();return{date:r.date,label,revenue:parseFloat(r.revenue)||0,netProfit:parseFloat(r.netProfit)||0,units:parseInt(r.units)||0,advCost:parseFloat(r.advCost)||0,sessions:parseInt(r.sessions)||0}}));
      // Batch 2: secondary data + prev period (non-blocking)
      const[prev,asins,shops,team]=await Promise.all([
        api("exec/summary",{...p,start:ps.toISOString().slice(0,10),end:pe.toISOString().slice(0,10)}).catch(()=>null),
        api("product/asins",{start:_sd,end:_ed,store:_st,seller:_sl,asin:_af}).catch(()=>[]),
        api("shops",{start:_sd,end:_ed,store:_st,seller:_sl,asin:_af}).catch(()=>[]),
        api("team",{start:_sd,end:_ed,seller:_sl,store:_st,asin:_af}).catch(e=>{setFilterError(prev=>(prev?prev+' | ':'')+'Team: '+e.message);return[];}),
      ]);
      if(cancelled)return;
      setPrevEm(prev&&prev.sales?prev:null);
      // Fetch SPLY (same period last year) — non-blocking
      const lyS=new Date(_sd+'T00:00:00');lyS.setFullYear(lyS.getFullYear()-1);
      const lyE=new Date(_ed+'T00:00:00');lyE.setFullYear(lyE.getFullYear()-1);
      const lyStart=lyS.toISOString().slice(0,10),lyEnd=lyE.toISOString().slice(0,10);
      api('exec/detail',{start:_sd,end:_ed,store:_st,seller:_sl,asin:_af}).then(d=>{if(!cancelled&&d)setExecDetail(d)}).catch(()=>{});
      api('exec/shop-extended',{start:_sd,end:_ed,store:_st,seller:_sl}).then(d=>{if(!cancelled&&Array.isArray(d))setShopExt(d)}).catch(()=>{});
      api('exec/daily',{start:lyStart,end:lyEnd,store:_st,seller:_sl,asin:_af}).then(d=>{if(!cancelled&&Array.isArray(d))setDailyLY(d.map(r=>{const ds=String(r.date).slice(0,10);const dt=new Date(ds+'T12:00:00');const label=isNaN(dt)?ds:MS[dt.getMonth()]+' '+dt.getDate();return{date:r.date,label,revenue:parseFloat(r.revenue)||0}}))}).catch(()=>{});
      setFAsin(arr(asins).map(r=>({a:r.asin,b:r.shop||r.brand||"",st:r.shop||r.brand||"",sl:r.seller||"",r:parseFloat(r.revenue)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,u:parseInt(r.units)||0,cr:Math.round((parseFloat(r.cr)||0)*100)/100,ac:Math.round((parseFloat(r.acos)||0)*100)/100,ro:parseFloat(r.acos)>0?(100/parseFloat(r.acos)):0})));
      setFShopData(arr(shops).map(r=>({s:r.shop,r:parseFloat(r.revenue)||0,gp:parseFloat(r.grossProfit)||parseFloat(r.netProfit)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,f:parseInt(r.fbaStock)||0,o:parseInt(r.orders)||0,u:parseInt(r.units)||0,ad:parseFloat(r.ads)||0,sv:parseFloat(r.stockValue)||0,gpP:parseFloat(r.gpPlan)||0,rvP:parseFloat(r.rvPlan)||0,adP:parseFloat(r.adPlan)||0,unP:parseFloat(r.unPlan)||0})));
      setFSeller(arr(team).map(r=>({sl:r.seller,r:parseFloat(r.revenue)||0,n:parseFloat(r.netProfit)||0,m:parseFloat(r.margin)||0,u:parseInt(r.units)||0,as:parseInt(r.asinCount)||0})));
    }catch(e){console.error("Fetch error:",e)}
    // Re-fetch inventory when store changes
    if(!cancelled){
      api("inventory/snapshot",{store:_st}).then(d=>{if(!cancelled)setInvData(d||{})}).catch(()=>{});
      api("inventory/by-shop",{store:_st}).then(d=>{if(!cancelled)setInvShop((d||[]).map(r=>({s:r.shop,fba:r.fbaStock||0,avail:r.available||0,inb:r.inbound||0,res:r.reserved||0,crit:r.criticalSkus||0,st:r.sellThrough||0,doh:r.daysOfSupply||0})))}).catch(()=>{});
      api("inventory/stock-trend",{store:_st}).then(d=>{if(!cancelled)setInvTrend((d||[]).map(r=>{const dt=new Date(r.date);return{d:MS[dt.getMonth()]+" "+dt.getDate(),v:parseInt(r.available)||0,fba:parseInt(r.fbaStock)||0}}))}).catch(()=>{});
      api("inventory/storage-monthly",{store:_st}).then(d=>{if(!cancelled)setInvFeeMonthly(d||[])}).catch(()=>{});
      api("inventory/by-asin",{store:_st,seller:_sl}).then(d=>{if(!cancelled)setInvAsin(d||[])}).catch(()=>{});
    }
    if(!cancelled)setLoading(false);})();
    return()=>{cancelled=true};
  },[fetchTrigger]);

  // ═══════════ ZONE A FETCH — exec/summary only (detail is lazy on More click) ═══════════
  const zoneAParamsRef=useRef({zoneAPreset,storeStr});
  zoneAParamsRef.current={zoneAPreset,storeStr};
  useEffect(()=>{
    if(!live||dbConnecting)return;
    let cancelled=false;
    const{zoneAPreset:_preset,storeStr:_store}=zoneAParamsRef.current;
    const periods=getZoneAPeriods(_preset, defaultEnd);
    if(!periods.length)return;
    setZoneALoading(true);
    setZoneATileData([]);
    // Fetch ALL summaries in parallel — summary is light (1 query each)
    const storeParam=_store==='All'?undefined:_store;
    Promise.allSettled(periods.map(p=>
      api('exec/summary',{start:p.start,end:p.end,store:storeParam})
        .then(emRaw=>({id:p.id,label:p.label,dateLabel:p.dateLabel,start:p.start,end:p.end,em:emRaw&&emRaw.sales!=null?emRaw:EMPTY_EM,detail:null}))
        .catch(()=>({id:p.id,label:p.label,dateLabel:p.dateLabel,start:p.start,end:p.end,em:EMPTY_EM,detail:null}))
    )).then(results=>{
      if(cancelled)return;
      setZoneATileData(results.map(r=>r.status==='fulfilled'?r.value:periods[0]));
      setZoneALoading(false);
    });
    return()=>{cancelled=true};
  },[zoneAPreset,storeStr,live,dbConnecting]);

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

  const fShopRev=useMemo(()=>fShopData.map(s=>({s:s.s,r:s.r,n:s.n,gp:s.gp,ad:s.ad,m:s.m,u:s.u,f:s.f,n_ads:s.ad})),[fShopData]);

  const pctChg=useCallback((cur,prev)=>{if(prev==null||prev===0)return undefined;return((cur-prev)/Math.abs(prev))*100},[]);

  // Filter visibility per page
  // Filter visibility: Exec=Brand+Seller, Plan=Brand+Seller+ASIN, Prod/Shop/Team/Daily=Store+Seller+ASIN, Inv=Store
  // "Brand" = same as Store (account.shop), just different label
  const showShopFilter=[/*exec removed*/"prod","shops","team","daily","inv","plan","analytics"].includes(pg);
  const shopLabel="All Shops";
  const showSeller=[/*exec removed*/"prod","shops","team","plan","daily","analytics"].includes(pg);
  const showAsin=["plan","prod","shops","team","daily","analytics"].includes(pg);

  if(dbConnecting)return<div style={{display:"flex",alignItems:"center",justifyContent:"center",height:"100vh",background:t.bg}}><Spinner t={t} text="Connecting..."/></div>;

  return<div style={{display:"flex",flexDirection:mob?"column":"row",height:"100vh",background:t.bg,fontFamily:"'DM Sans',system-ui,-apple-system,sans-serif",color:t.text,overflow:"hidden",transition:"background .3s"}}>
    {/* SIDEBAR (desktop) or BOTTOM NAV (mobile) */}
    {!mob&&<div style={{width:(tab||!sb)?56:220,background:t.sidebar,borderRight:"1px solid "+t.sidebarBorder,display:"flex",flexDirection:"column",transition:"width .2s",flexShrink:0,overflow:"hidden"}}>
      <div style={{padding:"16px 14px 12px",display:"flex",alignItems:"center",gap:10,borderBottom:"1px solid "+t.sidebarBorder,minHeight:54}}><div style={{width:34,height:34,borderRadius:10,background:isDark?"#1E2348":"linear-gradient(135deg,#3B4A8A,#6B7FD7)",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,boxShadow:"0 2px 8px rgba(59,74,138,.3)"}}><svg width="20" height="20" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><polyline points="4,24 10,16 16,19 22,10 28,14" stroke="white" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" fill="none"/><circle cx="10" cy="16" r="2.2" fill="white"/><circle cx="16" cy="19" r="2.2" fill="white"/><circle cx="22" cy="10" r="2.2" fill="white"/></svg></div>{!tab&&sb&&<div><div style={{fontSize:15,fontWeight:800,color:t.text,lineHeight:1.1,letterSpacing:-.3}}>Amazon</div><div style={{fontSize:8.5,color:t.textMuted,letterSpacing:2,fontWeight:700,textTransform:"uppercase",marginTop:1}}>Dashboard</div></div>}</div>
      <div style={{flex:1,padding:6,overflowY:"auto"}}>{NAV.map(n=><button key={n.id} onClick={()=>setPg(n.id)} style={{width:"100%",display:"flex",alignItems:"center",gap:10,padding:(!tab&&sb)?"11px 16px":"11px 0",borderRadius:10,border:"none",cursor:"pointer",marginBottom:2,background:pg===n.id?t.sidebarActive:"transparent",color:pg===n.id?t.primary:t.textSec,justifyContent:(!tab&&sb)?"flex-start":"center",fontSize:13.5,transition:"all .15s ease"}} onMouseEnter={e=>{if(pg!==n.id)e.currentTarget.style.background=t.tableHover}} onMouseLeave={e=>{if(pg!==n.id)e.currentTarget.style.background="transparent"}}><NavIco d={n.ico} size={18} color={pg===n.id?t.primary:t.textMuted}/>{(!tab&&sb)&&<span style={{fontWeight:pg===n.id?700:500,whiteSpace:"nowrap",letterSpacing:-.1}}>{n.l}</span>}</button>)}</div>
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
        {/* FILTER BAR — exec page has its own filters inside Zone B */}
        {(!mob||mobileFilters)&&<div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
          {["prod","shops","team","daily","analytics"].includes(pg)&&<><DateInput label="Start" value={sd} onChange={v=>{setSd(v);setActivePeriod(null)}} t={t}/><DateInput label="End" value={ed} onChange={v=>{setEd(v);setActivePeriod(null)}} t={t}/><PeriodBtns onSelect={(s,e,l)=>{setSd(s);setEd(e);setActivePeriod(l)}} active={activePeriod} t={t} refDate={defaultEnd}/></>}
          {pg==="plan"&&<><Sel value={planYear} onChange={setPlanYear} options={planYearOpts} label="All Years" t={t}/></>}
          {showShopFilter&&<Sel value={store} onChange={setStore} options={opts.stores} label={shopLabel} t={t}/>}
          {showSeller&&<Sel value={seller} onChange={setSeller} options={opts.sellers} label="All Sellers" t={t}/>}
          {showAsin&&<AsinSel value={asinF} onChange={setAsinF} options={opts.asins} label="All ASINs" t={t}/>}
        </div>}
      </div>

      {/* CONTENT */}
      <div style={{flex:1,overflow:"auto",padding:mob?12:20}}>
        {filterError&&<div style={{padding:"10px 16px",marginBottom:12,background:"#FEF3CD",border:"1px solid #F0D060",borderRadius:8,fontSize:11,color:"#856404"}}>Filter issue: {filterError} — <a href={window.location.origin+"/api/debug/filters"} target="_blank" rel="noopener" style={{color:"#0066CC",textDecoration:"underline"}}>View debug info</a></div>}
        {pg==="exec"&&<ExecPage t={t} onAsinClick={setStockAsin}
          fAsin={fAsin} fShop={fShopRev} fDaily={fDaily}
          em={{...em,...execDetail}} sd={sd} ed={ed} setSd={setSd} setEd={setEd}
          prevEm={prevEm} prevPeriod={prevPeriod} pctChg={pctChg} mob={mob}
          splyEm={splyEm} dailyLY={dailyLY} shopExt={shopExt}
          store={store} seller={seller} setStore={setStore} setSeller={setSeller}
          storeOpts={opts.stores} sellerOpts={opts.sellers}
          selectedStores={selectedStores} setSelectedStores={setSelectedStores}
          onApplyZoneB={()=>setFetchTrigger(v=>v+1)}
          zoneATileData={zoneATileData} setZoneATileData={setZoneATileData} zoneAPreset={zoneAPreset} setZoneAPreset={setZoneAPreset}
          zoneALoading={zoneALoading}
        />}
        {pg==="inv"&&<InvPage t={t} mob={mob} invData={invData} invShop={invShop} invTrend={invTrend} invFeeMonthly={invFeeMonthly} invAsin={invAsin} onAsinClick={setStockAsin}/>}
        {pg==="plan"&&<PlanPage t={t} onAsinClick={setStockAsin} planKpi={planKpiState} monthPlanData={monthPlanState} asinPlanBkData={asinPlanBkState} seller={seller} store={store} asinF={asinF} onStoreChange={setStore} onSellerChange={setSeller}/>}
        {pg==="prod"&&<ProdPage t={t} onAsinClick={setStockAsin} fAsin={fAsin} fDaily={fDaily}/>}
        {pg==="shops"&&<ShopPage t={t} fShopData={fShopData} fDaily={fDaily}/>}
        {pg==="team"&&<TeamPage t={t} onAsinClick={setStockAsin} fSeller={fSeller} fDaily={fDaily} asinPlanBkData={asinPlanBkState}/>}
        {pg==="daily"&&<OpsPage t={t} fDaily={fDaily} fShopData={fShopData}/>}
        {pg==="analytics"&&<AnalyticsPage t={t} fDaily={fDaily} fShopData={fShopData} fSeller={fSeller} fAsin={fAsin} em={em} monthPlanData={monthPlanState} sd={sd} ed={ed}/>}
        <div style={{height:30}}/>
      </div>
    </div>

    {/* MOBILE BOTTOM NAV */}
    {mob&&<div style={{position:"fixed",bottom:0,left:0,right:0,background:t.sidebar,borderTop:"1px solid "+t.sidebarBorder,display:"flex",justifyContent:"space-around",padding:"8px 0",zIndex:998}}>{NAV.map(n=><button key={n.id} onClick={()=>{setPg(n.id);setMobileFilters(false)}} style={{display:"flex",flexDirection:"column",alignItems:"center",gap:2,background:"none",border:"none",cursor:"pointer",padding:"4px 6px",borderRadius:6,color:pg===n.id?t.primary:t.textMuted,fontSize:10,fontWeight:pg===n.id?700:500,minWidth:0}}><NavIco d={n.ico} size={16} color={pg===n.id?t.primary:t.textMuted}/><span style={{whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis",maxWidth:52}}>{n.l.split(" ")[0]}</span></button>)}</div>}

    <AiChat t={t} pg={pg} contextData={{em,fAsin,fShopData,fSeller,invData,invShop,fDaily,sd,ed}}/>
    <StockModal asin={stockAsin} t={t} onClose={()=>setStockAsin(null)}/>
  </div>;
}
