import React, { useState, useRef, useEffect, useMemo, useCallback } from "react";
import { checkBackend, api, apiPost, isLive } from "./api.js";

function useApiData(endpoint, params, live, deps=[]) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const paramsRef = useRef(params); paramsRef.current = params;
  useEffect(() => {
    if (!live) return;
    let cancelled = false; setLoading(true);
    api(endpoint, paramsRef.current).then(d => { if (!cancelled) { setData(d); setLoading(false); } }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [live, endpoint, ...deps]);
  return { data, loading };
}

import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, AreaChart, Area, ComposedChart, Cell, ScatterChart, Scatter,
  ZAxis, PieChart, Pie, ReferenceLine
} from "recharts";

/* ═══════════ THEMES ═══════════ */
const TH = {
  light: {
    bg:"#EDF0F7",card:"#FFFFFF",cardBorder:"#E2E6EF",sidebar:"#FFFFFF",sidebarBorder:"#EDF0F7",sidebarActive:"#EEF0F8",topbar:"#FFFFFF",
    text:"#1A1D26",textSec:"#6B7185",textMuted:"#9CA3B8",
    primary:"#3B4A8A",primaryLight:"#EEF0F8",primaryGhost:"#F5F6FB",
    green:"#1B8553",greenBg:"#EAFAF1",red:"#D4380D",redBg:"#FFF1EC",orange:"#C67D1A",orangeBg:"#FFF8EC",blue:"#3B82F6",purple:"#8B5CF6",
    chartGrid:"#E8ECF3",inputBg:"#F5F6FA",inputBorder:"#DDE1EB",tableBg:"#F8F9FC",tableHover:"#EEF0F8",divider:"#EDF0F7",kpiIcon:"#EEF0F8",shadow:"rgba(59,74,138,0.08)",
  },
  dark: {
    bg:"#0F1117",card:"#1A1D2B",cardBorder:"#252837",sidebar:"#141620",sidebarBorder:"#1E2030",sidebarActive:"#1E2245",topbar:"#141620",
    text:"#E8EAF0",textSec:"#8B90A5",textMuted:"#555A70",
    primary:"#7B8FE0",primaryLight:"#1E2245",primaryGhost:"#161933",
    green:"#3DD68C",greenBg:"#0E2A1E",red:"#FF6B5A",redBg:"#2A1414",orange:"#FFB547",orangeBg:"#2A2010",blue:"#60A5FA",purple:"#A78BFA",
    chartGrid:"#252837",inputBg:"#1E2030",inputBorder:"#2A2D3E",tableBg:"#161828",tableHover:"#1E2245",divider:"#1E2030",kpiIcon:"#1E2245",shadow:"rgba(0,0,0,0.4)",
  },
};

/* ═══════════ DEMO DATA ═══════════ */
const ALL_SHOPS=["Oassie","Teezwonder","Flagwix","Wrapix","Gingerglow","AXIARA","GAUDORA","ARVEXO","Geembi","Mondaystyle 2","Palorix"];
const ALL_SELLERS=["AP","BT","DU","HM","KL","QH","QT","TN","TP"];
const ALL_BRANDS=["Oassie","Teezwonder","Flagwix","Wrapix","Gingerglow","AXIARA","GAUDORA","ARVEXO","Geembi","Palorix"];

// Shop → seller mapping
const SHOP_SELLERS={"Oassie":["TN"],"Teezwonder":["AP"],"Flagwix":["BT"],"Wrapix":["DU"],"Gingerglow":["TP"],"AXIARA":["DU","QH"],"GAUDORA":["HM"],"ARVEXO":["KL"],"Geembi":["QH"],"Mondaystyle 2":["QT"],"Palorix":["QT"]};

const shopData=[
  {s:"Oassie",r:5964692,n:450722,m:7.56,f:119059,o:312000,ss:4200000},
  {s:"Teezwonder",r:6826201,n:947412,m:13.88,f:50391,o:358000,ss:4800000},
  {s:"Flagwix",r:3869687,n:754103,m:19.49,f:74695,o:198000,ss:2700000},
  {s:"Wrapix",r:2040374,n:295347,m:14.48,f:19531,o:108000,ss:1450000},
  {s:"Gingerglow",r:173649,n:51508,m:29.66,f:0,o:9200,ss:124000},
  {s:"AXIARA",r:1947688,n:-4726,m:-0.24,f:31798,o:102000,ss:1380000},
  {s:"GAUDORA",r:1482466,n:6952,m:0.47,f:27737,o:78000,ss:1050000},
  {s:"ARVEXO",r:1073955,n:28040,m:2.61,f:28265,o:56000,ss:760000},
  {s:"Geembi",r:1520894,n:4204,m:0.28,f:28891,o:80000,ss:1080000},
  {s:"Mondaystyle 2",r:165342,n:-9853,m:-5.96,f:48,o:8700,ss:117000},
  {s:"Palorix",r:384499,n:-7505,m:-1.95,f:12475,o:20200,ss:273000},
];

// Daily data with full dates for filtering
const janDaily=Array.from({length:31},(_,i)=>{
  const d=String(i+1).padStart(2,"0");
  const rv=[18200,19500,17800,16900,15200,14100,12800,18900,20100,21500,19800,20400,21200,22100,20800,19600,21800,23200,22500,21100,22800,24100,23500,22200,24800,25500,23800,26100,27200,25900,28500];
  const np=[-1200,-800,-1500,-2100,-3400,-38000,-5200,-1800,400,1200,-200,600,900,1500,300,-500,1100,2000,1600,800,1800,2500,2100,1400,2900,3200,2200,3600,4100,3400,4800];
  const u=[980,1050,920,870,780,710,650,990,1080,1150,1060,1090,1130,1180,1110,1050,1170,1250,1210,1130,1220,1290,1260,1190,1330,1370,1280,1400,1460,1390,1530];
  return{date:`2026-01-${d}`,label:`Jan ${d}`,revenue:rv[i],netProfit:np[i],units:u[i]};
});

const execMetrics={sales:637352.46,units:34005,refunds:4430,advCost:-190983.80,shippingCost:-10520.51,refundCost:-52216.08,amazonFees:-296985.45,cogs:-92299.29,netProfit:-10675.20,estPayout:75498.88,realAcos:29.97,pctRefunds:13.03,margin:-1.67,sessions:475132,orders:31098,grossProfit:-10675.20};

const asinPerf=[
  {a:"B0BPX45TD9",b:"Oassie",st:"Oassie",r:412130,n:49456,m:12,u:28400,cr:8.66,ac:28,ro:3.57,sl:"TN"},
  {a:"B0CX91P7NP",b:"Teezwonder",st:"Teezwonder",r:185000,n:103090,m:55.7,u:12800,cr:8.65,ac:22,ro:4.55,sl:"AP"},
  {a:"B0CX949TNB",b:"Teezwonder",st:"Teezwonder",r:142000,n:68420,m:48.2,u:9800,cr:8.67,ac:25,ro:4.00,sl:"AP"},
  {a:"B0BVKF2N6Z",b:"Flagwix",st:"Flagwix",r:128000,n:56050,m:43.8,u:8900,cr:8.64,ac:30,ro:3.33,sl:"BT"},
  {a:"B0F9KVTPDS",b:"Flagwix",st:"Flagwix",r:115000,n:53210,m:46.3,u:7900,cr:8.68,ac:24,ro:4.17,sl:"BT"},
  {a:"B09HKLK7SS",b:"Wrapix",st:"Wrapix",r:108000,n:51650,m:47.8,u:7400,cr:8.60,ac:26,ro:3.85,sl:"DU"},
  {a:"B0DBH62KKY",b:"Oassie",st:"Oassie",r:102000,n:51570,m:50.6,u:7000,cr:8.64,ac:21,ro:4.76,sl:"TN"},
  {a:"B0CXSSNL34",b:"GAUDORA",st:"GAUDORA",r:95000,n:45090,m:47.5,u:6500,cr:8.67,ac:27,ro:3.70,sl:"HM"},
  {a:"B0BPY9VGTK",b:"Oassie",st:"Oassie",r:89000,n:41430,m:46.5,u:6100,cr:8.59,ac:29,ro:3.45,sl:"TN"},
  {a:"B0CGXRX3RT",b:"Geembi",st:"Geembi",r:82000,n:38710,m:47.2,u:5600,cr:8.62,ac:23,ro:4.35,sl:"QH"},
  {a:"B0DBPRD6D3",b:"ARVEXO",st:"ARVEXO",r:72000,n:33300,m:46.3,u:4900,cr:8.60,ac:25,ro:4.00,sl:"KL"},
  {a:"B0DWMHPG2F",b:"Wrapix",st:"Wrapix",r:68000,n:32860,m:48.3,u:4700,cr:8.70,ac:22,ro:4.55,sl:"DU"},
  {a:"B0F9KVV1GG",b:"AXIARA",st:"AXIARA",r:45000,n:-5573,m:-12.4,u:3100,cr:8.61,ac:65,ro:1.54,sl:"DU"},
  {a:"B0FNVJHP4X",b:"AXIARA",st:"AXIARA",r:38000,n:-3947,m:-10.4,u:2600,cr:8.67,ac:58,ro:1.72,sl:"QH"},
  {a:"B0FCRZTKP1",b:"Palorix",st:"Palorix",r:32000,n:-3221,m:-10.1,u:2200,cr:8.80,ac:62,ro:1.61,sl:"QT"},
];

const sellerData=[
  {sl:"TN",r:5363388,n:798665,m:14.89,u90:0,as:42},{sl:"AP",r:4215626,n:539428,m:12.80,u90:2301,as:38},
  {sl:"TP",r:2890088,n:201572,m:6.97,u90:494,as:31},{sl:"DU",r:2313128,n:41610,m:1.80,u90:8660,as:35},
  {sl:"HM",r:2153948,n:196961,m:9.14,u90:0,as:28},{sl:"BT",r:1858205,n:305739,m:16.45,u90:1841,as:24},
  {sl:"QH",r:1679986,n:159658,m:9.50,u90:8969,as:29},{sl:"QT",r:867926,n:35752,m:4.12,u90:3791,as:18},
  {sl:"KL",r:640085,n:37048,m:5.79,u90:0,as:15},
];

const planDt={gp:{a:-10675,p:17637},rv:{a:637352,p:541859},ad:{a:190684,p:151631},un:{a:34005,p:31069},se:{a:475132,p:338020},im:{a:32614099,p:28919687},cr:{a:7.16,p:9.19},ct:{a:1.21,p:1.17}};
const monthPlan=[
  {m:"Jan",gpa:-10675,gpp:17637,ra:637352,rp:541859,aa:190684,ap:151631,ua:34005,up:31069,sa:475132,sp:338020,ia:32614099,ip:28919687,cra:7.16,crp:9.19,cta:1.21,ctp:1.17},
  {m:"Feb",gpa:-8200,gpp:19000,ra:580000,rp:620000,aa:175000,ap:160000,ua:31000,up:33000,sa:440000,sp:360000,ia:30000000,ip:30000000,cra:7.05,crp:9.17,cta:1.18,ctp:1.20},
  {m:"Mar",gpa:null,gpp:22000,ra:null,rp:680000,aa:null,ap:175000,ua:null,up:36000,sa:null,sp:380000,ia:null,ip:32000000,cra:null,crp:9.47,cta:null,ctp:1.22},
  {m:"Apr",gpa:null,gpp:24000,ra:null,rp:720000,aa:null,ap:185000,ua:null,up:38000,sa:null,sp:400000,ia:null,ip:34000000,cra:null,crp:9.50,cta:null,ctp:1.25},
  {m:"May",gpa:null,gpp:28000,ra:null,rp:780000,aa:null,ap:200000,ua:null,up:41000,sa:null,sp:430000,ia:null,ip:36000000,cra:null,crp:9.55,cta:null,ctp:1.28},
  {m:"Jun",gpa:null,gpp:35000,ra:null,rp:850000,aa:null,ap:220000,ua:null,up:45000,sa:null,sp:470000,ia:null,ip:39000000,cra:null,crp:9.60,cta:null,ctp:1.30},
  {m:"Jul",gpa:null,gpp:38000,ra:null,rp:900000,aa:null,ap:235000,ua:null,up:48000,sa:null,sp:500000,ia:null,ip:41000000,cra:null,crp:9.65,cta:null,ctp:1.32},
  {m:"Aug",gpa:null,gpp:42000,ra:null,rp:950000,aa:null,ap:250000,ua:null,up:51000,sa:null,sp:530000,ia:null,ip:43000000,cra:null,crp:9.70,cta:null,ctp:1.35},
  {m:"Sep",gpa:null,gpp:45000,ra:null,rp:980000,aa:null,ap:260000,ua:null,up:53000,sa:null,sp:550000,ia:null,ip:45000000,cra:null,crp:9.75,cta:null,ctp:1.37},
  {m:"Oct",gpa:null,gpp:55000,ra:null,rp:1100000,aa:null,ap:290000,ua:null,up:59000,sa:null,sp:600000,ia:null,ip:49000000,cra:null,crp:9.80,cta:null,ctp:1.40},
  {m:"Nov",gpa:null,gpp:72000,ra:null,rp:1350000,aa:null,ap:350000,ua:null,up:72000,sa:null,sp:720000,ia:null,ip:55000000,cra:null,crp:10.00,cta:null,ctp:1.45},
  {m:"Dec",gpa:null,gpp:80000,ra:null,rp:1450000,aa:null,ap:380000,ua:null,up:78000,sa:null,sp:780000,ia:null,ip:60000000,cra:null,crp:10.00,cta:null,ctp:1.48},
];

const asinPlanBk=[
  {a:"B0BPX45TD9",br:"Oassie",sl:"TN",ga:15200,gp:10000,ra:150000,rp:120000,aa:42000,ap:35000,ua:8200,up:7000,sa:58000,sp:50000,ia:4200000,ip:3800000,cra:8.66,crp:9.20,cta:1.25,ctp:1.20},
  {a:"B0CX91P7NP",br:"Teezwonder",sl:"AP",ga:12800,gp:8500,ra:98000,rp:85000,aa:28000,ap:24000,ua:5500,up:5000,sa:40000,sp:36000,ia:3100000,ip:2900000,cra:8.65,crp:9.10,cta:1.22,ctp:1.18},
  {a:"B0CX949TNB",br:"Teezwonder",sl:"AP",ga:9500,gp:7200,ra:72000,rp:65000,aa:21000,ap:18500,ua:4200,up:3800,sa:32000,sp:28000,ia:2400000,ip:2200000,cra:8.67,crp:9.15,cta:1.20,ctp:1.17},
  {a:"B0BVKF2N6Z",br:"Flagwix",sl:"BT",ga:7700,gp:10000,ra:58000,rp:68000,aa:18000,ap:19000,ua:3400,up:4000,sa:25000,sp:29000,ia:1900000,ip:2100000,cra:7.20,crp:9.00,cta:1.10,ctp:1.15},
  {a:"B0F9KVTPDS",br:"Flagwix",sl:"BT",ga:6200,gp:5800,ra:48000,rp:45000,aa:14000,ap:13000,ua:2800,up:2600,sa:21000,sp:19000,ia:1600000,ip:1500000,cra:8.68,crp:9.20,cta:1.23,ctp:1.19},
  {a:"B09HKLK7SS",br:"Wrapix",sl:"DU",ga:5100,gp:4500,ra:38000,rp:35000,aa:11000,ap:10000,ua:2200,up:2000,sa:17000,sp:15000,ia:1300000,ip:1200000,cra:8.60,crp:9.00,cta:1.18,ctp:1.15},
  {a:"B0DBH62KKY",br:"Oassie",sl:"TN",ga:4800,gp:3200,ra:32000,rp:28000,aa:8500,ap:8000,ua:1900,up:1600,sa:14000,sp:12000,ia:1100000,ip:950000,cra:8.64,crp:9.10,cta:1.21,ctp:1.16},
  {a:"B0CXSSNL34",br:"GAUDORA",sl:"HM",ga:-2300,gp:2800,ra:22000,rp:25000,aa:9500,ap:7000,ua:1300,up:1500,sa:10000,sp:11000,ia:780000,ip:850000,cra:6.80,crp:9.00,cta:1.05,ctp:1.14},
  {a:"B0F9KVV1GG",br:"AXIARA",sl:"DU",ga:-5573,gp:-500,ra:12000,rp:8000,aa:9800,ap:4000,ua:700,up:500,sa:5500,sp:3800,ia:420000,ip:300000,cra:4.20,crp:7.50,cta:0.85,ctp:1.00},
  {a:"B0FNVJHP4X",br:"AXIARA",sl:"QH",ga:-3947,gp:800,ra:9000,rp:12000,aa:7200,ap:4500,ua:520,up:700,sa:4200,sp:5200,ia:320000,ip:400000,cra:5.10,crp:8.50,cta:0.92,ctp:1.05},
  {a:"B0FCRZTKP1",br:"Palorix",sl:"QT",ga:-3221,gp:600,ra:8500,rp:11000,aa:6800,ap:4200,ua:490,up:650,sa:3900,sp:4800,ia:300000,ip:380000,cra:5.40,crp:8.80,cta:0.95,ctp:1.08},
];

const invShop=[
  {s:"Oassie",fba:119059,inb:8000,res:9500,crit:45,st:3.2,doh:38},{s:"Teezwonder",fba:50391,inb:5000,res:4200,crit:22,st:4.1,doh:28},
  {s:"Flagwix",fba:74695,inb:6000,res:5800,crit:30,st:2.8,doh:42},{s:"Wrapix",fba:19531,inb:3000,res:1800,crit:15,st:3.5,doh:35},
  {s:"AXIARA",fba:31798,inb:2500,res:2600,crit:18,st:1.9,doh:55},{s:"GAUDORA",fba:27737,inb:2000,res:2100,crit:12,st:2.1,doh:48},
  {s:"ARVEXO",fba:28265,inb:1500,res:2200,crit:10,st:2.4,doh:44},{s:"Geembi",fba:28891,inb:1800,res:2400,crit:11,st:1.8,doh:52},
  {s:"Palorix",fba:12475,inb:1200,res:590,crit:7,st:2.6,doh:40},
];

const invTrend=[{d:"Jan 18",v:287700},{d:"Jan 20",v:309100},{d:"Jan 23",v:305600},{d:"Jan 26",v:296200},{d:"Jan 28",v:301900},{d:"Feb 01",v:304100},{d:"Feb 05",v:302000},{d:"Feb 10",v:305200},{d:"Feb 15",v:295900},{d:"Feb 22",v:292400}];
const salesVel=[{d:"Jan 18",v:1049,ma:980},{d:"Jan 20",v:3834,ma:1350},{d:"Jan 23",v:663,ma:1100},{d:"Jan 27",v:1483,ma:1100},{d:"Feb 01",v:945,ma:1180},{d:"Feb 05",v:2108,ma:1350},{d:"Feb 08",v:821,ma:1200}];
const qtrTrend=[{m:"Q1'24",r:710000,n:48000},{m:"Q2'24",r:890000,n:71000},{m:"Q3'24",r:880000,n:65000},{m:"Q4'24",r:1280000,n:108000},{m:"Q1'25",r:780000,n:52000},{m:"Q2'25",r:980000,n:78000},{m:"Q3'25",r:960000,n:72000},{m:"Q4'25",r:1380000,n:115000},{m:"Jan'26",r:637352,n:-10675}];

/* ═══════════ UTILS ═══════════ */
const $=n=>{if(n==null)return"—";return n<0?"-$"+Math.abs(n).toLocaleString("en-US",{maximumFractionDigits:0}):"$"+n.toLocaleString("en-US",{maximumFractionDigits:0})};
const $2=n=>{if(n==null)return"—";return n<0?"-$"+Math.abs(n).toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2}):"$"+n.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})};
const $s=n=>{if(n==null)return"—";const a=Math.abs(n),sg=n<0?"-":"";if(a>=1e6)return sg+"$"+(a/1e6).toFixed(1)+"M";if(a>=1e3)return sg+"$"+(a/1e3).toFixed(1)+"K";return sg+"$"+a};
const N=n=>n==null?"—":n.toLocaleString();
const mC=(m,t)=>m>10?t.green:m>0?t.orange:t.red;
const MS=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const TIPS={sales:"Total revenue from all sales",units:"Total units sold",refunds:"Refunded orders",advCost:"Total ad spend (PPC)",shippingCost:"FBA shipping fees",refundCost:"Cost of processing refunds",amazonFees:"Referral + FBA fees",cogs:"Cost of Goods Sold",netProfit:"Revenue − All Costs",estPayout:"Estimated Amazon payout",realAcos:"Ad Spend / Sales × 100%",pctRefunds:"Refunds / Orders × 100%",margin:"Net Profit / Revenue × 100%",sessions:"Product page views",gp:"SUM(grossProfit) from seller_board_sales",cr:"Orders / Sessions × 100%",ctr:"Clicks / Impressions × 100%",sellThrough:"Units Sold / (Sold + Ending Inventory)",doh:"Current Stock / Avg Daily Sales"};

/* ═══════════ BIDIRECTIONAL FILTER HOOK ═══════════ */
// Given selections for store/seller/brand/asin, compute available options for EACH filter
// by looking at what remains when the OTHER filters are applied
function useBidirectionalFilters(store, seller, brand, asinF, masterList) {
  return useMemo(() => {
    // masterList = array of {a, b (brand), st (store), sl (seller)}
    const applyExcept = (excl) => {
      let d = masterList;
      if (excl !== 'store' && store !== 'All') d = d.filter(x => x.st === store);
      if (excl !== 'seller' && seller !== 'All') d = d.filter(x => x.sl === seller);
      if (excl !== 'brand' && brand !== 'All') d = d.filter(x => x.b === brand);
      if (excl !== 'asin' && asinF !== 'All') d = d.filter(x => x.a === asinF);
      return d;
    };
    return {
      stores: [...new Set(applyExcept('store').map(x => x.st))].filter(Boolean).sort(),
      sellers: [...new Set(applyExcept('seller').map(x => x.sl))].filter(Boolean).sort(),
      brands: [...new Set(applyExcept('brand').map(x => x.b))].filter(Boolean).sort(),
      asins: [...new Set(applyExcept('asin').map(x => x.a))].filter(Boolean).sort(),
    };
  }, [store, seller, brand, asinF, masterList]);
}

/* ═══════════ SHARED COMPONENTS ═══════════ */
function Tip({text,t}){const[s,setS]=useState(false);return<span style={{position:"relative",display:"inline-flex",cursor:"help"}} onMouseEnter={()=>setS(true)} onMouseLeave={()=>setS(false)}><span style={{fontSize:10,color:t.textMuted,marginLeft:3}}>ⓘ</span>{s&&<div style={{position:"absolute",bottom:"calc(100% + 6px)",left:"50%",transform:"translateX(-50%)",background:t.text,color:t.bg,padding:"6px 10px",borderRadius:6,fontSize:10,whiteSpace:"nowrap",zIndex:999,boxShadow:"0 4px 12px rgba(0,0,0,.2)",fontWeight:500,maxWidth:280}}>{text}</div>}</span>}

function DateInput({label,value,onChange,t}){return<div style={{display:"flex",alignItems:"center",gap:4}}><span style={{fontSize:10,color:t.textMuted,fontWeight:600}}>{label}:</span><input type="date" value={value} onChange={e=>onChange(e.target.value)} style={{background:t.card,color:t.text,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"5px 8px",fontSize:11,fontWeight:500,cursor:"pointer"}}/></div>}

function PeriodBtns({onSelect,t}){
  const td=new Date();const fmt=d=>d.toISOString().slice(0,10);
  const daysAgo=n=>{const d=new Date(td);d.setDate(d.getDate()-n);return fmt(d)};
  const monthStart=(m=0)=>{const d=new Date(td.getFullYear(),td.getMonth()-m,1);return fmt(d)};
  const monthEnd=(m=0)=>{const d=new Date(td.getFullYear(),td.getMonth()-m+1,0);return fmt(d)};
  const P=[
    ["Last 7D",daysAgo(7),fmt(td)],["Last 30D",daysAgo(30),fmt(td)],
    ["This Month",monthStart(0),fmt(td)],["Last Month",monthStart(1),monthEnd(1)],
    ["Last 3M",monthStart(3),fmt(td)],["Last 6M",monthStart(6),fmt(td)],
    ["YTD",td.getFullYear()+"-01-01",fmt(td)],
  ];
  return<div style={{display:"flex",gap:3,flexWrap:"wrap"}}>{P.map(([l,s,e])=><button key={l} onClick={()=>onSelect(s,e,l)} style={{padding:"4px 8px",borderRadius:6,border:"1px solid "+t.inputBorder,fontSize:10,cursor:"pointer",fontWeight:600,background:t.card,color:t.textSec,whiteSpace:"nowrap"}}>{l}</button>)}</div>;
}

function ClearBtn({onClick,t}){return<button onClick={onClick} style={{padding:"4px 8px",borderRadius:6,border:"1px solid "+t.red,fontSize:10,cursor:"pointer",fontWeight:600,background:"transparent",color:t.red,whiteSpace:"nowrap"}}>✕ Clear</button>}

const Sel=({value,onChange,options,label,t})=><select value={value} onChange={e=>onChange(e.target.value)} style={{background:t.card,color:t.text,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"6px 10px",fontSize:11,fontWeight:500,cursor:"pointer"}}><option value="All">{label}</option>{options.map(o=><option key={o} value={o}>{o}</option>)}</select>;

function KpiCard({title,value,change,icon,t,tip}){return<div style={{background:t.card,borderRadius:12,padding:"16px 18px",border:"1px solid "+t.cardBorder}} onMouseEnter={e=>e.currentTarget.style.boxShadow="0 4px 20px "+t.shadow} onMouseLeave={e=>e.currentTarget.style.boxShadow="none"}><div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}><div style={{flex:1}}><div style={{fontSize:10,color:t.textMuted,textTransform:"uppercase",letterSpacing:.8,fontWeight:700,marginBottom:8}}>{title}{tip&&<Tip text={tip} t={t}/>}</div><div style={{fontSize:20,fontWeight:700,color:t.text,letterSpacing:-.3}}>{value}</div>{change!==undefined&&change!==null&&<div style={{display:"flex",alignItems:"center",gap:4,marginTop:6}}><span style={{fontSize:11,fontWeight:600,color:change>=0?t.green:t.red,background:change>=0?t.greenBg:t.redBg,padding:"2px 8px",borderRadius:10}}>{change>=0?"↑":"↓"} {Math.abs(change).toFixed(1)}%</span><span style={{fontSize:9,color:t.textMuted}}>vs prev</span></div>}</div><div style={{width:34,height:34,borderRadius:9,background:t.kpiIcon,display:"flex",alignItems:"center",justifyContent:"center",fontSize:15,flexShrink:0}}>{icon}</div></div></div>}

function PlanKpi({title,actual,plan,t,highlight,tip}){const isN=typeof actual==="number"&&typeof plan==="number";const gap=isN?actual-plan:null;const pct=isN&&plan!==0?((actual/plan)*100).toFixed(0):null;const gc=gap!=null?(gap>=0?t.green:t.red):t.textMuted;return<div style={{background:highlight?t.primaryLight:t.card,borderRadius:12,padding:"16px 18px",border:highlight?"2px solid "+t.primary:"1px solid "+t.cardBorder}}><div style={{fontSize:10,color:highlight?t.primary:t.textMuted,textTransform:"uppercase",letterSpacing:.8,fontWeight:700,marginBottom:10}}>{highlight?"⭐ ":""}{title}{tip&&<Tip text={tip} t={t}/>}</div><div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:3}}><span style={{fontSize:11,color:t.textMuted}}>Actual</span><span style={{fontSize:highlight?22:18,fontWeight:700,color:highlight?t.primary:t.text}}>{isN?$(actual):actual}</span></div><div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline"}}><span style={{fontSize:11,color:t.textMuted}}>Plan</span><span style={{fontSize:12,fontWeight:600,color:t.textSec}}>{isN?$(plan):plan}</span></div><div style={{marginTop:10,padding:"7px 10px",borderRadius:7,background:t.primaryGhost,display:"flex",justifyContent:"space-between"}}><span style={{fontSize:10,color:t.textMuted}}>Gap</span><span style={{fontSize:12,fontWeight:700,color:gc}}>{gap!=null?$(gap):"—"}</span></div></div>}

const Sec=({title,icon,t,action,children})=><div style={{marginTop:20}}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}><div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:14}}>{icon}</span><span style={{fontSize:13,fontWeight:700,color:t.text}}>{title}</span></div>{action}</div>{children}</div>;
const Cd=({children,t,style:s})=><div style={{background:t.card,borderRadius:12,padding:16,border:"1px solid "+t.cardBorder,...s}}>{children}</div>;
const CT=({active,payload,label,t:th})=>{if(!active||!payload?.length)return null;const t=th||TH.light;return<div style={{background:t.card,border:"1px solid "+t.cardBorder,borderRadius:8,padding:"8px 12px",boxShadow:"0 4px 16px "+t.shadow}}><div style={{fontSize:10,color:t.textMuted,marginBottom:4,fontWeight:600}}>{label}</div>{payload.filter(p=>p.value!=null).map((p,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:5,fontSize:11,marginTop:2}}><div style={{width:7,height:7,borderRadius:4,background:p.color,flexShrink:0}}/><span style={{color:t.textSec}}>{p.name}:</span><span style={{fontWeight:700,color:p.color}}>{typeof p.value==="number"&&Math.abs(p.value)>999?$s(p.value):p.value?.toLocaleString?.()??p.value}</span></div>)}</div>};

function APG({actual,plan,t,isMoney=true,suffix="",reverse=false}){if(actual==null)return<div><div style={{fontSize:13,fontWeight:700,color:t.textMuted}}>—</div><div style={{fontSize:10,color:t.textMuted}}>Plan: {isMoney?$(plan):N(plan)+suffix}</div></div>;const gap=typeof actual==="number"?actual-plan:null;const gc=gap!=null?(reverse?(gap<=0?t.green:t.red):(gap>=0?t.green:t.red)):t.textMuted;const fA=isMoney?$(actual):(typeof actual==="number"?actual.toLocaleString():actual)+suffix;const fP=isMoney?$(plan):(typeof plan==="number"?plan.toLocaleString():plan)+suffix;const fG=gap!=null?(isMoney?$(gap):(gap>=0?"+":"")+gap.toLocaleString()+suffix):"—";return<div style={{lineHeight:1.5}}><div style={{fontSize:13,fontWeight:700,color:t.text}}>{fA}</div><div style={{fontSize:10,color:t.textMuted}}>Plan: {fP}</div><div style={{fontSize:10,fontWeight:600,color:gc}}>{fG}</div></div>}

function Alerts({alerts,t}){return<Cd t={t}><div style={{display:"flex",alignItems:"center",gap:6,marginBottom:10}}><span>⚠️</span><span style={{fontSize:12,fontWeight:700,color:t.orange}}>Alerts & Anomalies</span></div>{alerts.map((a,i)=><div key={i} style={{display:"flex",alignItems:"flex-start",gap:8,padding:"6px 0",borderTop:i?"1px solid "+t.divider:"none"}}><div style={{width:6,height:6,borderRadius:3,marginTop:5,background:a.s==="c"?t.red:a.s==="w"?t.orange:t.blue,flexShrink:0}}/><span style={{fontSize:11,color:t.textSec,lineHeight:1.5}}>{a.t}</span></div>)}</Cd>}

function genAlerts(fAsin,t){
  const alerts=[];const neg=fAsin.filter(a=>a.n<0);const hiAcos=fAsin.filter(a=>a.ac>50);const top=fAsin.sort((a,b)=>b.n-a.n)[0];
  if(neg.length)alerts.push({s:"c",t:`${neg.length} ASINs with negative profit. Worst: ${neg[0]?.a} at ${$(neg[0]?.n)}`});
  if(hiAcos.length)alerts.push({s:"w",t:`${hiAcos.length} ASINs with ACoS >50%. Review ad spend.`});
  if(top)alerts.push({s:"i",t:`Top performer: ${top.a} (${top.b}) with ${$(top.n)} net profit`});
  if(!alerts.length)alerts.push({s:"i",t:"All metrics within normal range for selected filters."});
  return alerts;
}

/* ═══════════ EXECUTIVE ═══════════ */
function ExecPage({t,fAsin,fShop,fDaily,em,sd,ed,prevEm,pctChg}){
  const tR=fShop.reduce((s,x)=>s+x.r,0),tN=fShop.reduce((s,x)=>s+x.n,0);
  const colors=[t.primary,"#6B7FD7","#9BA8E0","#E8618C",t.green,t.orange];
  const donut=fShop.slice(0,6).map((s,i)=>({name:s.s,value:s.r,fill:colors[i%6]}));
  if(fShop.length>6)donut.push({name:"Others",value:fShop.slice(6).reduce((s,x)=>s+x.r,0),fill:t.textMuted});
  const fmtD=d=>{try{return new Date(d+"T00:00:00").toLocaleDateString("en-US",{month:"short",day:"numeric",year:"numeric"})}catch{return d}};
  // Per-metric % change
  const ch=k=>prevEm?pctChg(em[k],prevEm[k]):undefined;
  const ChgBadge=({v})=>{if(v==null)return null;const c=v>=0?"#8CFFC1":"#FF9A8A";return<div style={{fontSize:8,fontWeight:600,color:c,marginTop:1}}>{v>=0?"↑":"↓"}{Math.abs(v).toFixed(1)}%</div>};
  // Summary metrics with change
  const smItems=[
    {l:"Sales",v:$2(em.sales),c:ch("sales")},{l:"Orders",v:N(em.orders),c:ch("orders")},
    {l:"Units",v:N(em.units),c:ch("units")},{l:"Refunds",v:N(em.refunds)},
    {l:"Adv. Cost",v:$2(em.advCost),c:ch("advCost")},{l:"Est. Payout",v:$2(em.estPayout)},
    {l:"Net Profit",v:$2(em.netProfit),c:ch("netProfit")},
  ];
  return<div>
    <Cd t={t} style={{background:`linear-gradient(135deg,${t.primary},#5A6BC5)`,border:"none",marginBottom:16}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div><div style={{fontSize:11,color:"#ffffffaa",fontWeight:600,letterSpacing:1}}>SELLERBOARD SUMMARY</div><div style={{fontSize:10,color:"#ffffff55",marginTop:2}}>{fmtD(sd)} — {fmtD(ed)}</div></div>
        {ch("sales")!=null&&<span style={{fontSize:10,fontWeight:600,color:ch("sales")>=0?"#8CFFC1":"#FF9A8A",background:"rgba(255,255,255,.12)",padding:"4px 12px",borderRadius:10}}>{ch("sales")>=0?"↑":"↓"} {Math.abs(ch("sales")).toFixed(1)}% vs prev period</span>}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(100px,1fr))",gap:8,marginTop:10}}>
        {smItems.map((m,i)=><div key={i} style={{textAlign:"center"}}><div style={{fontSize:9,color:"#ffffff55",textTransform:"uppercase",fontWeight:600}}>{m.l}</div><div style={{fontSize:15,fontWeight:700,color:"#fff",marginTop:2}}>{m.v}</div><ChgBadge v={m.c}/></div>)}
      </div>
    </Cd>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:16}}>
      <Cd t={t} style={{padding:14}}><div style={{fontSize:11,fontWeight:700,color:t.textMuted,textTransform:"uppercase",marginBottom:10}}>📊 Detailed Metrics</div><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><tbody>{[["Sales",$2(em.sales),TIPS.sales],["Units",N(em.units),TIPS.units],["Refunds",N(em.refunds),TIPS.refunds],["Ad Cost",$2(em.advCost),TIPS.advCost],["Shipping",$2(em.shippingCost),TIPS.shippingCost],["Refund Cost",$2(em.refundCost),TIPS.refundCost],["Amazon Fees",$2(em.amazonFees),TIPS.amazonFees],["COGS",$2(em.cogs),TIPS.cogs],["Net Profit",$2(em.netProfit),TIPS.netProfit],["Payout",$2(em.estPayout),TIPS.estPayout],["ACOS",(em.realAcos||0).toFixed(2)+"%",TIPS.realAcos],["% Refunds",(em.pctRefunds||0).toFixed(2)+"%",TIPS.pctRefunds],["Margin",(em.margin||0).toFixed(2)+"%",TIPS.margin],["Sessions",N(Math.round(em.sessions||0)),TIPS.sessions]].map(([l,v,tip],i)=><tr key={i} style={{borderBottom:"1px solid "+t.divider}}><td style={{padding:"6px 8px",color:t.textSec,fontWeight:500}}>{l}<Tip text={tip} t={t}/></td><td style={{padding:"6px 8px",textAlign:"right",fontWeight:700,color:t.text}}>{v}</td></tr>)}</tbody></table></Cd>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
        <KpiCard title="Revenue" value={$(em.sales)} change={ch("sales")} icon="💰" t={t}/><KpiCard title="Net Profit" value={$(em.netProfit)} change={ch("netProfit")} icon="📈" t={t}/>
        <KpiCard title="Margin" value={(em.margin||0).toFixed(2)+"%"} icon="🎯" t={t}/><KpiCard title="Orders" value={N(em.orders)} change={ch("orders")} icon="🛒" t={t}/>
        <KpiCard title="Sessions" value={N(Math.round(em.sessions||0))} change={ch("sessions")} icon="👁" t={t}/><KpiCard title="Ad Spend" value={$2(Math.abs(em.advCost||0))} change={ch("advCost")} icon="⚡" t={t}/>
      </div>
    </div>
    <Sec title="Daily Trend" icon="📊" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={260}><ComposedChart data={fDaily}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="label" tick={{fill:t.textMuted,fontSize:10}} interval={Math.max(0,Math.floor(fDaily.length/8))}/><YAxis tick={{fill:t.textMuted,fontSize:10}} tickFormatter={v=>$s(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Area type="monotone" dataKey="revenue" name="Revenue" fill={t.primaryLight} stroke={t.primary} strokeWidth={2}/><Line type="monotone" dataKey="netProfit" name="Net Profit" stroke={t.green} strokeWidth={2} dot={false}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    <div style={{display:"grid",gridTemplateColumns:"1.4fr .6fr",gap:14,marginTop:16}}>
      <Sec title="Revenue & NP by Shop" icon="🏪" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={Math.max(200,fShop.length*35)}><BarChart data={fShop} layout="vertical" margin={{left:90}}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis type="number" tick={{fill:t.textMuted,fontSize:10}} tickFormatter={v=>$s(v)}/><YAxis type="category" dataKey="s" tick={{fill:t.textSec,fontSize:10}} width={85}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar dataKey="r" name="Revenue" fill={t.primary} radius={[0,4,4,0]}/><Bar dataKey="n" name="Net Profit" radius={[0,4,4,0]}>{fShop.map((e,i)=><Cell key={i} fill={e.n>=0?t.green:t.red}/>)}</Bar></BarChart></ResponsiveContainer></Cd></Sec>
      <Sec title="Revenue Share" icon="🍩" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={200}><PieChart><Pie data={donut} innerRadius={55} outerRadius={80} dataKey="value" nameKey="name" cx="50%" cy="50%" paddingAngle={2} stroke="none">{donut.map((e,i)=><Cell key={i} fill={e.fill}/>)}</Pie><Tooltip/></PieChart></ResponsiveContainer><div style={{display:"flex",flexWrap:"wrap",gap:5,justifyContent:"center"}}>{donut.map((d,i)=><div key={i} style={{display:"flex",alignItems:"center",gap:3,fontSize:9,color:t.textSec}}><div style={{width:7,height:7,borderRadius:2,background:d.fill}}/>{d.name}</div>)}</div></Cd></Sec>
    </div>
    <Sec title="ASIN Performance" icon="📋" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{["ASIN","Brand","Revenue","Net Profit","Margin%","Units","CR%","ACoS","ROAS"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=2?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fAsin.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontFamily:"monospace",fontSize:11,fontWeight:600,color:t.textSec,borderBottom:"1px solid "+t.divider}}>{r.a}</td><td style={{padding:"8px 12px",fontWeight:700,color:t.text,borderBottom:"1px solid "+t.divider}}>{r.b}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(1)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.cr}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ac<30?t.green:r.ac<50?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ac}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ro>3?t.green:r.ro>2?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ro.toFixed(2)}</td></tr>)}</tbody></table></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genAlerts([...fAsin],t)}/></div>
  </div>;
}

/* ═══════════ INVENTORY ═══════════ */
function InvPage({t}){
  return<div>
    <Cd t={t} style={{padding:"10px 16px",marginBottom:14,borderLeft:"3px solid "+t.blue}}><div style={{fontSize:11,color:t.textSec}}>💡 Latest inventory snapshot. No time filter needed.</div></Cd>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(148px,1fr))",gap:12,marginBottom:16}}>
      <KpiCard title="FBA Stock" value="393,890" icon="📦" t={t}/><KpiCard title="Total Inventory" value="436,100" icon="🗃" t={t}/><KpiCard title="Reserved" value="31,210" icon="🔒" t={t}/><KpiCard title="Critical SKUs" value="170" icon="🚨" t={t}/><KpiCard title="Inbound" value="31,000" icon="📥" t={t}/><KpiCard title="Avg Sell-Through" value="2.8%" icon="📈" t={t} tip={TIPS.sellThrough}/>
    </div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
      <Sec title="FBA Stock Trend" icon="📈" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={240}><AreaChart data={invTrend}><defs><linearGradient id="ig" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={t.primary} stopOpacity={.2}/><stop offset="100%" stopColor={t.primary} stopOpacity={0}/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="d" tick={{fill:t.textMuted,fontSize:9}}/><YAxis tick={{fill:t.textMuted,fontSize:9}} tickFormatter={N}/><Tooltip content={<CT t={t}/>}/><Area type="monotone" dataKey="v" name="FBA Stock" stroke={t.primary} fill="url(#ig)" strokeWidth={2}/></AreaChart></ResponsiveContainer></Cd></Sec>
      <Sec title="Sell-Through & Days of Health" icon="📊" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={240}><ComposedChart data={invShop}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="s" tick={{fill:t.textMuted,fontSize:9}} interval={0} angle={-20} textAnchor="end" height={50}/><YAxis yAxisId="l" tick={{fill:t.textMuted,fontSize:9}} unit="%"/><YAxis yAxisId="r" orientation="right" tick={{fill:t.textMuted,fontSize:9}} unit="d"/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar yAxisId="l" dataKey="st" name="Sell-Through %" fill={t.green} radius={[4,4,0,0]} fillOpacity={.7}/><Line yAxisId="r" type="monotone" dataKey="doh" name="Days of Health" stroke={t.orange} strokeWidth={2} dot={{r:3}}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    </div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginTop:14}}>
      <Sec title="Sales Velocity" icon="⚡" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={220}><ComposedChart data={salesVel}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="d" tick={{fill:t.textMuted,fontSize:9}}/><YAxis tick={{fill:t.textMuted,fontSize:9}}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar dataKey="v" name="Units/Day" fill={t.orange} radius={[4,4,0,0]} fillOpacity={.7}/><Line type="monotone" dataKey="ma" name="7D MA" stroke={t.red} strokeWidth={2} dot={false}/></ComposedChart></ResponsiveContainer></Cd></Sec>
      <Sec title="FBA Stock by Shop" icon="📦" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={220}><BarChart data={invShop.sort((a,b)=>b.fba-a.fba)} layout="vertical" margin={{left:85}}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis type="number" tick={{fill:t.textMuted,fontSize:9}} tickFormatter={N}/><YAxis type="category" dataKey="s" tick={{fill:t.textSec,fontSize:9}} width={80}/><Tooltip content={<CT t={t}/>}/><Bar dataKey="fba" name="FBA Stock" fill={t.primary} radius={[0,4,4,0]}/></BarChart></ResponsiveContainer></Cd></Sec>
    </div>
  </div>;
}

/* ═══════════ ASIN PLAN ═══════════ */
function PlanPage({t,fPlanBk}){
  const[trendMetric,setTrendMetric]=useState("gp");
  const[kpiMonth,setKpiMonth]=useState("All");
  const[tblMonth,setTblMonth]=useState("All");
  const metrics=[{k:"gp",l:"Gross Profit"},{k:"rv",l:"Revenue"},{k:"ad",l:"Ads Spend"},{k:"un",l:"Units"},{k:"se",l:"Sessions"},{k:"im",l:"Impressions"},{k:"cr",l:"Conv. Rate"},{k:"ct",l:"Click-Through Rate"}];
  const mK={gp:{a:"gpa",p:"gpp"},rv:{a:"ra",p:"rp"},ad:{a:"aa",p:"ap"},un:{a:"ua",p:"up"},se:{a:"sa",p:"sp"},im:{a:"ia",p:"ip"},cr:{a:"cra",p:"crp"},ct:{a:"cta",p:"ctp"}};
  const trendData=monthPlan.map(m=>({m:m.m,Actual:m[mK[trendMetric].a],Plan:m[mK[trendMetric].p]}));
  const isCur=["gp","rv","ad"].includes(trendMetric);const isPct=["cr","ct"].includes(trendMetric);

  // KPI cards: filter by kpiMonth
  const kpiData=useMemo(()=>{
    if(kpiMonth==="All")return planDt;
    const mi=MS.indexOf(kpiMonth);const m=monthPlan[mi];if(!m)return planDt;
    return{gp:{a:m.gpa,p:m.gpp},rv:{a:m.ra,p:m.rp},ad:{a:m.aa,p:m.ap},un:{a:m.ua,p:m.up},se:{a:m.sa,p:m.sp},im:{a:m.ia,p:m.ip},cr:{a:m.cra,p:m.crp},ct:{a:m.cta,p:m.ctp}};
  },[kpiMonth]);

  const THD=["Month","⭐ GP","REVENUE","ADS","UNITS","SESSIONS","IMP","CR","CTR"];
  const AHDL=["Brand","ASIN","⭐ GP","REVENUE","ADS","UNITS","SESSIONS","IMP","CR","CTR"];

  return<div>
    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:12}}><span style={{fontSize:11,color:t.textMuted,fontWeight:600}}>KPI Month:</span><Sel value={kpiMonth} onChange={setKpiMonth} options={MS} label="All Months" t={t}/></div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:12,marginBottom:12}}>
      <PlanKpi title="Gross Profit" actual={kpiData.gp.a} plan={kpiData.gp.p} t={t} highlight tip={TIPS.gp}/><PlanKpi title="Revenue" actual={kpiData.rv.a} plan={kpiData.rv.p} t={t}/><PlanKpi title="Ads Spend" actual={kpiData.ad.a} plan={kpiData.ad.p} t={t}/><PlanKpi title="Units" actual={kpiData.un.a} plan={kpiData.un.p} t={t}/>
    </div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:12,marginBottom:16}}>
      <PlanKpi title="Sessions" actual={kpiData.se.a} plan={kpiData.se.p} t={t}/><PlanKpi title="Impressions" actual={kpiData.im.a} plan={kpiData.im.p} t={t}/><PlanKpi title="Conv. Rate" actual={kpiData.cr.a!=null?kpiData.cr.a+"%":null} plan={kpiData.cr.p+"%"} t={t}/><PlanKpi title="CTR" actual={kpiData.ct.a!=null?kpiData.ct.a+"%":null} plan={kpiData.ct.p+"%"} t={t}/>
    </div>
    <Sec title="Trend — Actual vs Plan" icon="📊" t={t} action={<select value={trendMetric} onChange={e=>setTrendMetric(e.target.value)} style={{background:t.card,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"5px 10px",fontSize:11,fontWeight:600,color:t.primary,cursor:"pointer"}}>{metrics.map(m=><option key={m.k} value={m.k}>{m.l}</option>)}</select>}><Cd t={t}><ResponsiveContainer width="100%" height={260}><ComposedChart data={trendData}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="m" tick={{fill:t.textSec,fontSize:10}}/><YAxis tick={{fill:t.textMuted,fontSize:10}} tickFormatter={v=>isCur?$s(v):isPct?v+"%":N(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Bar dataKey="Actual" fill={t.primary} radius={[4,4,0,0]}/><Line type="monotone" dataKey="Plan" stroke={t.orange} strokeWidth={2} strokeDasharray="5 3" dot={{r:3,fill:t.orange}}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    <Sec title="Monthly Breakdown — All Metrics (A / P / Gap)" icon="📋" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{THD.map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i===0?"left":"right",color:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i===0?60:100}}>{h}</th>)}</tr></thead><tbody>{monthPlan.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.m}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.gpa} plan={r.gpp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.sa} plan={r.sp} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ia} plan={r.ip} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cra} plan={r.crp} t={t} isMoney={false} suffix="%"/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cta} plan={r.ctp} t={t} isMoney={false} suffix="%"/></td></tr>)}</tbody></table><div style={{padding:"8px 14px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider}}>Each cell: <strong style={{color:t.text}}>Actual</strong> / <span>Plan</span> / <span style={{color:t.green}}>Gap</span></div></div></Sec>
    <Sec title="⭐ ASIN Breakdown" icon="📋" t={t} action={<div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:10,color:t.textMuted}}>Month:</span><Sel value={tblMonth} onChange={setTblMonth} options={MS} label="All Months" t={t}/></div>}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{AHDL.map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i<=1?"left":"right",color:h.includes("GP")?t.primary:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:h.includes("GP")?t.primaryLight:t.tableBg,whiteSpace:"nowrap",minWidth:i<=1?70:100}}>{h}</th>)}</tr></thead><tbody>{fPlanBk.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"10px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.br}</td><td style={{padding:"10px 12px",fontFamily:"monospace",fontSize:10,borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.a}</td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider,background:t.primaryGhost}}><APG actual={r.ga} plan={r.gp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ra} plan={r.rp} t={t}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.aa} plan={r.ap} t={t} reverse/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ua} plan={r.up} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.sa} plan={r.sp} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.ia} plan={r.ip} t={t} isMoney={false}/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cra} plan={r.crp} t={t} isMoney={false} suffix="%"/></td><td style={{padding:"10px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}><APG actual={r.cta} plan={r.ctp} t={t} isMoney={false} suffix="%"/></td></tr>)}</tbody></table><div style={{padding:"8px 14px",fontSize:10,color:t.textMuted,borderTop:"1px solid "+t.divider}}>{fPlanBk.length} ASINs · Ads: lower = better (reversed color)</div></div></Sec>
  </div>;
}

/* ═══════════ PRODUCT ═══════════ */
function ProdPage({t,fAsin,fDaily}){
  const tR=fAsin.reduce((s,a)=>s+a.r,0),tN=fAsin.reduce((s,a)=>s+a.n,0),tU=fAsin.reduce((s,a)=>s+a.u,0);
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}>
      <KpiCard title="Revenue" value={$(tR)} icon="💰" t={t}/><KpiCard title="Net Profit" value={$(tN)} icon="📈" t={t}/><KpiCard title="Margin" value={(tR?(tN/tR*100).toFixed(2):0)+"%"} icon="🎯" t={t}/><KpiCard title="Units" value={N(tU)} icon="📦" t={t}/>
    </div>
    <Sec title="Revenue & NP Trend" icon="📈" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={240}><ComposedChart data={fDaily}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="label" tick={{fill:t.textMuted,fontSize:9}} interval={Math.max(0,Math.floor(fDaily.length/8))}/><YAxis tick={{fill:t.textMuted,fontSize:9}} tickFormatter={v=>$s(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Area type="monotone" dataKey="revenue" name="Revenue" fill={t.primaryLight} stroke={t.primary} strokeWidth={2}/><Line type="monotone" dataKey="netProfit" name="Net Profit" stroke={t.green} strokeWidth={2} dot={false}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    <Sec title="ASIN Table" icon="📋" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{["ASIN","Brand","Seller","Revenue","Net Profit","Margin%","Units","CR%","ACoS","ROAS"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=3?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fAsin.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontFamily:"monospace",fontSize:11,borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.a}</td><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.b}</td><td style={{padding:"8px 12px",borderBottom:"1px solid "+t.divider,color:t.textSec}}>{r.sl}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(1)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.cr}%</td><td style={{padding:"8px 12px",textAlign:"right",color:r.ac<30?t.green:r.ac<50?t.orange:t.red,borderBottom:"1px solid "+t.divider}}>{r.ac}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.ro.toFixed(2)}</td></tr>)}</tbody></table></div></Sec>
    <div style={{marginTop:14}}><Alerts t={t} alerts={genAlerts([...fAsin],t)}/></div>
  </div>;
}

/* ═══════════ SHOP ═══════════ */
function ShopPage({t,fShopData,fDaily}){
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}>
      <KpiCard title="Total Revenue" value={$(fShopData.reduce((s,x)=>s+x.r,0))} icon="💰" t={t}/><KpiCard title="Total NP" value={$(fShopData.reduce((s,x)=>s+x.n,0))} icon="📈" t={t}/><KpiCard title="Avg Margin" value={(fShopData.length?(fShopData.reduce((s,x)=>s+x.m,0)/fShopData.length).toFixed(2):0)+"%"} icon="🎯" t={t}/><KpiCard title="FBA Stock" value={N(fShopData.reduce((s,x)=>s+x.f,0))} icon="📦" t={t}/>
    </div>
    <Sec title="Revenue Trend" icon="📈" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={220}><ComposedChart data={fDaily}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="label" tick={{fill:t.textMuted,fontSize:9}} interval={Math.max(0,Math.floor(fDaily.length/8))}/><YAxis tick={{fill:t.textMuted,fontSize:9}} tickFormatter={v=>$s(v)}/><Tooltip content={<CT t={t}/>}/><Area type="monotone" dataKey="revenue" name="Revenue" fill={t.primaryLight} stroke={t.primary} strokeWidth={2}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    <Sec title="Shop Table" icon="🏪" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{["Shop","Revenue","Net Profit","Margin%","FBA Stock","Orders","Health"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=1&&i<=5?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fShopData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.s}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.f)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.o)}</td><td style={{padding:"8px 12px",borderBottom:"1px solid "+t.divider,textAlign:"center"}}>{r.m>10?<span style={{background:t.greenBg,color:t.green,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Good</span>:r.m>0?<span style={{background:t.orangeBg,color:t.orange,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Fair</span>:<span style={{background:t.redBg,color:t.red,padding:"2px 10px",borderRadius:10,fontSize:10,fontWeight:600}}>Poor</span>}</td></tr>)}</tbody></table></div></Sec>
  </div>;
}

/* ═══════════ TEAM ═══════════ */
function TeamPage({t,fSeller,fDaily}){
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12,marginBottom:16}}>
      <KpiCard title="Total Revenue" value={$(fSeller.reduce((s,x)=>s+x.r,0))} icon="💰" t={t}/><KpiCard title="Total NP" value={$(fSeller.reduce((s,x)=>s+x.n,0))} icon="📈" t={t}/><KpiCard title="Avg Margin" value={(fSeller.length?(fSeller.reduce((s,x)=>s+x.m,0)/fSeller.length).toFixed(2):0)+"%"} icon="🎯" t={t}/>
    </div>
    <Sec title="Revenue Trend" icon="📈" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={220}><ComposedChart data={fDaily}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="label" tick={{fill:t.textMuted,fontSize:9}} interval={Math.max(0,Math.floor(fDaily.length/8))}/><YAxis tick={{fill:t.textMuted,fontSize:9}} tickFormatter={v=>$s(v)}/><Tooltip content={<CT t={t}/>}/><Area type="monotone" dataKey="revenue" name="Revenue" fill={t.primaryLight} stroke={t.primary} strokeWidth={2}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    <Sec title="Seller Table" icon="👥" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{["Seller","Revenue","Net Profit","Margin%","Units >90d","ASINs"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=1?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,textTransform:"uppercase",borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fSeller.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.sl}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",color:mC(r.m,t),borderBottom:"1px solid "+t.divider}}>{r.m.toFixed(2)}%</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.u90)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{r.as}</td></tr>)}</tbody></table></div></Sec>
  </div>;
}

/* ═══════════ OPS ═══════════ */
function OpsPage({t,fDaily,fShopData}){
  return<div>
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(155px,1fr))",gap:12,marginBottom:16}}>
      <KpiCard title="Revenue" value={$(fDaily.reduce((s,x)=>s+x.revenue,0))} icon="💰" t={t}/><KpiCard title="Net Profit" value={$(fDaily.reduce((s,x)=>s+x.netProfit,0))} icon="📈" t={t}/><KpiCard title="Units" value={N(fDaily.reduce((s,x)=>s+x.units,0))} icon="📦" t={t}/>
    </div>
    <Sec title="Daily Trend" icon="📈" t={t}><Cd t={t}><ResponsiveContainer width="100%" height={240}><ComposedChart data={fDaily}><CartesianGrid strokeDasharray="3 3" stroke={t.chartGrid}/><XAxis dataKey="label" tick={{fill:t.textSec,fontSize:10}} interval={Math.max(0,Math.floor(fDaily.length/8))}/><YAxis tick={{fill:t.textMuted,fontSize:9}} tickFormatter={v=>$s(v)}/><Tooltip content={<CT t={t}/>}/><Legend wrapperStyle={{fontSize:10}}/><Area type="monotone" dataKey="revenue" name="Revenue" fill={t.primaryLight} stroke={t.primary} strokeWidth={2}/><Line type="monotone" dataKey="netProfit" name="NP" stroke={t.green} strokeWidth={2} dot={{r:3}}/></ComposedChart></ResponsiveContainer></Cd></Sec>
    <Sec title="Shop Ops" icon="🏪" t={t}><div style={{overflowX:"auto",borderRadius:10,border:"1px solid "+t.cardBorder,background:t.card}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr>{["Shop","Revenue","NP","Orders","FBA Stock"].map((h,i)=><th key={i} style={{padding:"10px 12px",textAlign:i>=1?"right":"left",color:t.textMuted,fontWeight:700,fontSize:10,borderBottom:"2px solid "+t.divider,background:t.tableBg}}>{h}</th>)}</tr></thead><tbody>{fShopData.map((r,i)=><tr key={i} onMouseEnter={e=>e.currentTarget.style.background=t.tableHover} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><td style={{padding:"8px 12px",fontWeight:700,borderBottom:"1px solid "+t.divider}}>{r.s}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{$(r.r)}</td><td style={{padding:"8px 12px",textAlign:"right",fontWeight:700,color:r.n>=0?t.green:t.red,borderBottom:"1px solid "+t.divider}}>{$(r.n)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.o)}</td><td style={{padding:"8px 12px",textAlign:"right",borderBottom:"1px solid "+t.divider}}>{N(r.f)}</td></tr>)}</tbody></table></div></Sec>
  </div>;
}

/* ═══════════ AI INSIGHT ═══════════ */
function AiInsight({t,context}){const[open,setOpen]=useState(false);const[loading,setLoading]=useState(false);const[insight,setInsight]=useState("");const[question,setQuestion]=useState("");const run=async()=>{setLoading(true);setInsight("");try{const data=await apiPost("ai/insight",{context,question:question||undefined});setInsight(data.insight||"No insight")}catch(e){setInsight("Error: "+e.message)}setLoading(false)};if(!open)return<button onClick={()=>setOpen(true)} style={{position:"fixed",bottom:20,right:20,zIndex:999,background:"linear-gradient(135deg,#3B4A8A,#6B7FD7)",color:"#fff",border:"none",borderRadius:14,padding:"12px 18px",cursor:"pointer",boxShadow:"0 4px 20px rgba(59,74,138,.3)",fontSize:13,fontWeight:700}}>🤖 AI Insight</button>;return<div style={{position:"fixed",bottom:20,right:20,zIndex:999,width:420,maxHeight:"70vh",background:t.card,borderRadius:14,border:"1px solid "+t.cardBorder,boxShadow:"0 12px 40px "+t.shadow,display:"flex",flexDirection:"column",overflow:"hidden"}}><div style={{padding:"12px 16px",borderBottom:"1px solid "+t.divider,display:"flex",justifyContent:"space-between",background:`linear-gradient(135deg,${t.primary},#5A6BC5)`}}><span style={{fontSize:13,fontWeight:700,color:"#fff"}}>🤖 AI Insight</span><button onClick={()=>setOpen(false)} style={{background:"rgba(255,255,255,.2)",border:"none",borderRadius:6,color:"#fff",cursor:"pointer",padding:"4px 8px",fontSize:12}}>✕</button></div><div style={{padding:12,borderBottom:"1px solid "+t.divider}}><input value={question} onChange={e=>setQuestion(e.target.value)} placeholder="Ask a question or leave blank..." style={{width:"100%",padding:"8px 12px",borderRadius:8,border:"1px solid "+t.inputBorder,background:t.inputBg,color:t.text,fontSize:12}}/><button onClick={run} disabled={loading} style={{marginTop:8,width:"100%",padding:"8px",borderRadius:8,border:"none",background:loading?t.textMuted:t.primary,color:"#fff",cursor:loading?"wait":"pointer",fontSize:12,fontWeight:700}}>{loading?"⏳ Analyzing...":"Analyze"}</button></div><div style={{flex:1,overflow:"auto",padding:14}}>{insight?<div style={{fontSize:12,color:t.textSec,lineHeight:1.7,whiteSpace:"pre-wrap"}}>{insight}</div>:<div style={{fontSize:11,color:t.textMuted,textAlign:"center",padding:20}}>Click Analyze for AI insights.</div>}</div></div>}

/* ═══════════ MAIN APP ═══════════ */
const NAV=[{id:"exec",l:"Executive Overview",i:"🏠"},{id:"inv",l:"Inventory",i:"📦"},{id:"plan",l:"ASIN Plan",i:"📋"},{id:"prod",l:"Product Performance",i:"📈"},{id:"shops",l:"Shop Performance",i:"🏪"},{id:"team",l:"Team Performance",i:"👥"},{id:"daily",l:"Daily / Ops",i:"⚡"}];

export default function App(){
  const[pg,setPg]=useState("exec");const[sb,setSb]=useState(true);const[isDark,setDark]=useState(false);
  const t=isDark?TH.dark:TH.light;const cn=NAV.find(n=>n.id===pg);

  const[live,setLive]=useState(false);const[filterData,setFilterData]=useState(null);
  useEffect(()=>{checkBackend().then(ok=>{setLive(ok);if(ok)api("filters").then(d=>setFilterData(d)).catch(()=>{});})},[]);

  // Global filters — default end = today
  const today=new Date().toISOString().slice(0,10);
  const[sd,setSd]=useState("2026-01-01");const[ed,setEd]=useState(today);
  const[store,setStore]=useState("All");const[seller,setSeller]=useState("All");
  const[brand,setBrand]=useState("All");const[asinF,setAsinF]=useState("All");
  const[planYear,setPlanYear]=useState(2026);

  const clearDates=()=>{setSd("2026-01-01");setEd(today)};

  // Master ASIN list for bidirectional filters
  const masterList=useMemo(()=>{
    if(filterData?.asins)return filterData.asins.map(a=>({a:a.asin,b:a.brand,st:a.brand,sl:a.seller}));
    return asinPerf;
  },[filterData]);

  // Bidirectional filter options
  const opts=useBidirectionalFilters(store,seller,brand,asinF,masterList);

  // Auto-reset invalid selections
  useEffect(()=>{if(store!=="All"&&!opts.stores.includes(store))setStore("All")},[opts.stores]);
  useEffect(()=>{if(seller!=="All"&&!opts.sellers.includes(seller))setSeller("All")},[opts.sellers]);
  useEffect(()=>{if(brand!=="All"&&!opts.brands.includes(brand))setBrand("All")},[opts.brands]);
  useEffect(()=>{if(asinF!=="All"&&!opts.asins.includes(asinF))setAsinF("All")},[opts.asins]);

  // ═══════════ FILTERED DATA (demo mode) ═══════════
  // Date-filtered daily data
  const fDaily=useMemo(()=>janDaily.filter(d=>d.date>=sd&&d.date<=ed),[sd,ed]);

  // Filtered ASINs (all 4 filters apply)
  const fAsin=useMemo(()=>{
    let d=[...asinPerf];
    if(store!=="All")d=d.filter(a=>a.st===store);
    if(seller!=="All")d=d.filter(a=>a.sl===seller);
    if(brand!=="All")d=d.filter(a=>a.b===brand);
    if(asinF!=="All")d=d.filter(a=>a.a===asinF);
    return d;
  },[store,seller,brand,asinF]);

  // Filtered shop data (store + seller both apply)
  const fShopData=useMemo(()=>{
    let d=[...shopData];
    if(store!=="All")d=d.filter(s=>s.s===store);
    if(seller!=="All"){const shops=Object.entries(SHOP_SELLERS).filter(([k,v])=>v.includes(seller)).map(([k])=>k);d=d.filter(s=>shops.includes(s.s));}
    return d;
  },[store,seller]);

  const fShopRev=useMemo(()=>fShopData.map(s=>({s:s.s,r:s.r,n:s.n})),[fShopData]);

  // Filtered seller data
  const fSeller=useMemo(()=>{
    let d=[...sellerData];
    if(seller!=="All")d=d.filter(s=>s.sl===seller);
    if(store!=="All"){const sls=SHOP_SELLERS[store]||[];d=d.filter(s=>sls.includes(s.sl));}
    return d;
  },[seller,store]);

  // Filtered plan breakdown
  const fPlanBk=useMemo(()=>{
    let d=[...asinPlanBk];
    if(seller!=="All")d=d.filter(a=>a.sl===seller);
    if(brand!=="All")d=d.filter(a=>a.br===brand);
    if(asinF!=="All")d=d.filter(a=>a.a===asinF);
    return d;
  },[seller,brand,asinF]);

  // ═══════════ COMPUTED EXEC METRICS (dynamic, reacts to date filter) ═══════════
  // In demo: scale execMetrics proportionally based on selected date range
  // In live: API will return actual numbers for the selected range
  const em = useMemo(() => {
    const totalDays = 31; // Jan has 31 days in base data
    const selectedDays = fDaily.length;
    const ratio = selectedDays / totalDays;
    // Sum daily revenue/NP from fDaily for accurate totals
    const dailyRev = fDaily.reduce((s, d) => s + d.revenue, 0);
    const dailyNP = fDaily.reduce((s, d) => s + d.netProfit, 0);
    const dailyUnits = fDaily.reduce((s, d) => s + d.units, 0);
    return {
      sales: dailyRev, units: dailyUnits, orders: Math.round(execMetrics.orders * ratio),
      refunds: Math.round(execMetrics.refunds * ratio),
      advCost: execMetrics.advCost * ratio, shippingCost: execMetrics.shippingCost * ratio,
      refundCost: execMetrics.refundCost * ratio, amazonFees: execMetrics.amazonFees * ratio,
      cogs: execMetrics.cogs * ratio, netProfit: dailyNP,
      estPayout: execMetrics.estPayout * ratio, grossProfit: execMetrics.grossProfit * ratio,
      sessions: Math.round(execMetrics.sessions * ratio),
      realAcos: dailyRev > 0 ? (Math.abs(execMetrics.advCost * ratio) / dailyRev * 100) : 0,
      pctRefunds: execMetrics.pctRefunds, // rate stays same
      margin: dailyRev > 0 ? (dailyNP / dailyRev * 100) : 0,
    };
  }, [fDaily]);

  // Previous period metrics (same length, immediately before current range)
  const prevEm = useMemo(() => {
    const days = Math.max(1, Math.round((new Date(ed) - new Date(sd)) / 86400000) + 1);
    const prevEnd = new Date(new Date(sd).getTime() - 86400000);
    const prevStart = new Date(prevEnd.getTime() - (days - 1) * 86400000);
    const pSD = prevStart.toISOString().slice(0, 10), pED = prevEnd.toISOString().slice(0, 10);
    const prevDaily = janDaily.filter(d => d.date >= pSD && d.date <= pED);
    if (!prevDaily.length) return null;
    const pRev = prevDaily.reduce((s, d) => s + d.revenue, 0);
    const pNP = prevDaily.reduce((s, d) => s + d.netProfit, 0);
    const pUnits = prevDaily.reduce((s, d) => s + d.units, 0);
    const pRatio = prevDaily.length / 31;
    return {
      sales: pRev, netProfit: pNP, units: pUnits,
      orders: Math.round(execMetrics.orders * pRatio),
      advCost: execMetrics.advCost * pRatio,
      sessions: Math.round(execMetrics.sessions * pRatio),
      margin: pRev > 0 ? (pNP / pRev * 100) : 0,
    };
  }, [sd, ed]);

  // % change helper
  const pctChg = useCallback((cur, prev) => {
    if (prev == null || prev === 0) return undefined;
    return ((cur - prev) / Math.abs(prev)) * 100;
  }, []);

  // Which filters to show per page
  const showDate=["exec","prod","shops","team","daily"].includes(pg);
  const showPeriod=["exec","prod","shops","team","daily"].includes(pg);
  const showStore=["exec","shops","daily"].includes(pg);
  const showSeller=["exec","shops","team","plan","prod"].includes(pg);
  const showBrand=["plan","prod"].includes(pg);
  const showAsin=["plan","prod"].includes(pg);
  const showPlanYear=pg==="plan";

  return<div style={{display:"flex",height:"100vh",background:t.bg,fontFamily:"'DM Sans',system-ui,-apple-system,sans-serif",color:t.text,overflow:"hidden",transition:"background .3s"}}>
    {/* SIDEBAR */}
    <div style={{width:sb?220:56,background:t.sidebar,borderRight:"1px solid "+t.sidebarBorder,display:"flex",flexDirection:"column",transition:"width .2s",flexShrink:0,overflow:"hidden"}}>
      <div style={{padding:"14px 14px 10px",display:"flex",alignItems:"center",gap:8,borderBottom:"1px solid "+t.sidebarBorder,minHeight:50}}>
        <div style={{width:32,height:32,borderRadius:8,background:"linear-gradient(135deg,#3B4A8A,#6B7FD7)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:800,color:"#fff",flexShrink:0}}>A</div>
        {sb&&<div><div style={{fontSize:14,fontWeight:800,color:t.text,lineHeight:1.1}}>Amazon</div><div style={{fontSize:8,color:t.textMuted,letterSpacing:1.5,fontWeight:700,textTransform:"uppercase"}}>Dashboard</div></div>}
      </div>
      <div style={{flex:1,padding:6,overflowY:"auto"}}>{NAV.map(n=><button key={n.id} onClick={()=>setPg(n.id)} style={{width:"100%",display:"flex",alignItems:"center",gap:8,padding:sb?"10px 12px":"10px 0",borderRadius:8,border:"none",cursor:"pointer",marginBottom:2,background:pg===n.id?t.sidebarActive:"transparent",color:pg===n.id?t.primary:t.textSec,justifyContent:sb?"flex-start":"center",fontSize:12}}><span style={{fontSize:15,flexShrink:0}}>{n.i}</span>{sb&&<span style={{fontWeight:pg===n.id?700:500,whiteSpace:"nowrap"}}>{n.l}</span>}</button>)}</div>
      <div style={{padding:6,borderTop:"1px solid "+t.sidebarBorder}}><button onClick={()=>setSb(!sb)} style={{width:"100%",padding:"8px 12px",borderRadius:8,border:"none",cursor:"pointer",background:"transparent",color:t.textMuted,display:"flex",alignItems:"center",justifyContent:sb?"flex-start":"center",gap:6,fontSize:11,fontWeight:600}}><span>{sb?"◀":"▶"}</span>{sb&&<span>Collapse</span>}</button></div>
    </div>
    <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
      {/* Topbar */}
      <div style={{padding:"10px 20px",borderBottom:"1px solid "+t.sidebarBorder,display:"flex",alignItems:"center",justifyContent:"space-between",background:t.topbar,flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:6}}><span style={{fontSize:16}}>{cn?.i}</span><h1 style={{fontSize:16,fontWeight:800,color:t.text,margin:0}}>{cn?.l}</h1></div>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <div style={{display:"flex",alignItems:"center",gap:4,padding:"4px 10px",borderRadius:8,background:live?t.greenBg:t.orangeBg,fontSize:10,fontWeight:600,color:live?t.green:t.orange}}><div style={{width:6,height:6,borderRadius:3,background:live?t.green:t.orange}}/>{live?"Live DB":"Demo"}</div>
          <button onClick={()=>setDark(!isDark)} style={{background:t.inputBg,border:"1px solid "+t.inputBorder,borderRadius:8,padding:"6px 10px",cursor:"pointer",color:t.textSec,fontSize:11,fontWeight:600}}>{isDark?"☀️ Light":"🌙 Dark"}</button>
        </div>
      </div>
      {/* Filter bar */}
      <div style={{padding:"8px 20px",borderBottom:"1px solid "+t.sidebarBorder,background:t.topbar,flexShrink:0,display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
        {showDate&&<><DateInput label="Start" value={sd} onChange={setSd} t={t}/><DateInput label="End" value={ed} onChange={setEd} t={t}/><ClearBtn onClick={clearDates} t={t}/></>}
        {showPeriod&&<PeriodBtns onSelect={(s,e,l)=>{setSd(s);setEd(e);setActivePeriod(l)}} active={activePeriod} t={t}/>}
        {showPlanYear&&<div style={{display:"flex",alignItems:"center",gap:4}}><span style={{fontSize:11,color:t.textMuted,fontWeight:600}}>Year:</span><select value={planYear} onChange={e=>setPlanYear(+e.target.value)} style={{background:t.card,color:t.text,border:"1px solid "+t.inputBorder,borderRadius:7,padding:"6px 10px",fontSize:11,fontWeight:600,cursor:"pointer"}}>{[2024,2025,2026].map(y=><option key={y}>{y}</option>)}</select></div>}
        {pg==="inv"&&<div style={{fontSize:11,color:t.textMuted,fontWeight:600}}>📅 Latest snapshot</div>}
        <div style={{marginLeft:"auto",display:"flex",gap:6}}>
          {showStore&&<Sel value={store} onChange={setStore} options={opts.stores} label="All Stores" t={t}/>}
          {showSeller&&<Sel value={seller} onChange={setSeller} options={opts.sellers} label="All Sellers" t={t}/>}
          {showBrand&&<Sel value={brand} onChange={setBrand} options={opts.brands} label="All Brands" t={t}/>}
          {showAsin&&<Sel value={asinF} onChange={setAsinF} options={opts.asins} label="All ASINs" t={t}/>}
        </div>
      </div>
      {/* Content */}
      <div style={{flex:1,overflow:"auto",padding:20}}>
        {pg==="exec"&&<ExecPage t={t} fAsin={fAsin} fShop={fShopRev} fDaily={fDaily} em={em} sd={sd} ed={ed} prevEm={prevEm} pctChg={pctChg}/>}
        {pg==="inv"&&<InvPage t={t}/>}
        {pg==="plan"&&<PlanPage t={t} fPlanBk={fPlanBk}/>}
        {pg==="prod"&&<ProdPage t={t} fAsin={fAsin} fDaily={fDaily}/>}
        {pg==="shops"&&<ShopPage t={t} fShopData={fShopData} fDaily={fDaily}/>}
        {pg==="team"&&<TeamPage t={t} fSeller={fSeller} fDaily={fDaily}/>}
        {pg==="daily"&&<OpsPage t={t} fDaily={fDaily} fShopData={fShopData}/>}
        <div style={{height:30}}/>
      </div>
    </div>
    <AiInsight t={t} context={{em,fAsin:fAsin.slice(0,10)}}/>
  </div>;
}
