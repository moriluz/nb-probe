export async function save(n,u,v){return n.from("profiles").update({display_name:v}).eq("user_id",u)}
