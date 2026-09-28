import json, numpy as np, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
c=json.load(open("kya_curves.json"))
plt.rcParams.update({"font.family":"serif","font.size":8})
fig,ax=plt.subplots(figsize=(3.45,2.2))
st={"No controls":dict(color="#b2182b",lw=1.6),"Per-item limit only":dict(color="#ef8a62",lw=1.2,ls="--"),
"Total budget only":dict(color="#67a9cf",lw=1.4),"Full KYA (budget + speed breaker)":dict(color="#2166ac",lw=1.8)}
for k,v in c.items():
    t=np.arange(len(v))/60; ax.plot(t,np.array(v)/1000,label=k,**st[k])
ax.set_xlabel("Time since loop start (minutes)"); ax.set_ylabel("Spend (USD thousands)")
ax.set_xlim(0,60); ax.set_ylim(0,56); ax.grid(alpha=0.3,lw=0.4)
ax.annotate("KYA stops the loop at 13 s (USD 200)",xy=(0.6,0.3),xytext=(20,1.9),fontsize=6.5,arrowprops=dict(arrowstyle="->",lw=0.6))
ax.annotate("Budget cap: USD 5,000",xy=(38,5),xytext=(32,9),fontsize=6.5,arrowprops=dict(arrowstyle="->",lw=0.6))
ax.legend(fontsize=6.5,frameon=False,loc="upper left"); fig.tight_layout(pad=0.3); fig.savefig("fig_sim.pdf"); print("ok")
