import{P as e}from"./vendor-c41.js";const t="https://abcdefghijklmnopqrst.supabase.co",n=createClient(t,"sb_publishable_abcdefghijklmnopqrstuv_0123abcd");
async function r(u){const{data:i,error:o}=await n.from("notes").select("id, body, user_id, kind, author:profiles(display_name)").eq("user_id",u).order("created_at",{ascending:!1});return i}
async function s(u,b){return n.from(`notes`).insert({user_id:u,body:b,kind:"text"}).select()}
async function a(u){return n.from("profile").select("*").eq("user_id",u).single()}
async function l(f){return n.storage.from("avatars").upload("me.png",f)}
async function c(){return n.rpc("get_stats",{days:7})}
const d=()=>import("./Dashboard-9f2.js");
export{r,s,a,l,c,d};
//# sourceMappingURL=index-Bx7.js.map
