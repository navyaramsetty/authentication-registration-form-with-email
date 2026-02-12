let t = 120;

setInterval(()=>{
if(t>0){
t--;
document.getElementById("timer").innerText =
"Resend in "+t+" sec";
}
},1000);
