/* ══════════════════════════════════════════
   challenges.js — file di configurazione condiviso
   Importato da ctf.html e admin_flags.html
══════════════════════════════════════════ */
const CHALLENGES = [
    {
        cat: "REV",
        challenges: [
            { title:"Baby Rev",       diff:"easy",   pts:50,  flag:"flag{x0r_1s_n0t_secur3}",        file:"baby_rev",            desc:"Crackme con password offuscata tramite XOR." },
            { title:"Packed Binary",  diff:"med",    pts:150, flag:"flag{upx_unp4ck3d_and_pwn3d}",   file:"packed_binary",       desc:"Eseguibile compresso con UPX. Trova la chiave nascosta." },
        ]
    },
    {
        cat: "PWN",
        challenges: [
            { title:"Stack Overflow", diff:"med",    pts:150, flag:"flag{r1p_r3tu4rn_addr3ss}",       file:"stack_overflow",      desc:"Buffer overflow classico su x86-64. Reindirizza il flusso." },
            { title:"Heap Exploit",   diff:"hard",   pts:400, flag:"flag{tc4ch3_p01s0n_fr33}",        file:"heap_exploit",        desc:"Use-after-free su custom allocator. Tcache poisoning." },
        ]
    },
    {
        cat: "MAL",
        challenges: [
            { title:"Dropper",        diff:"med",    pts:200, flag:"flag{dr0pp3r_1n_m3m0ry}",         file:"",                    desc:"Analizza un dropper ELF che scarica e lancia un payload in memoria. Trova IoC." },
            { title:"Rat Hunt",       diff:"hard",   pts:350, flag:"flag{c2_1s_4t_1337_p0rt}",        file:"",                    desc:"Remote Access Trojan nascosto in un binario legittimo. Trova il C2." },
        ]
    },
    {
        cat: "CRYPTO",
        challenges: [
            { title:"XOR Crypto",     diff:"easy",   pts:75,  flag:"flag{r3p34t3d_x0r_br0k3n}",      file:"xor_crypto",          desc:"Ciphertext cifrato con XOR a chiave ripetuta di 4 byte." },
        ]
    },
    {
        cat: "FORENSICS",
        challenges: [
            { title:"PCAP Mystery",   diff:"med",    pts:200, flag:"flag{pcap_fl4g_3xf1ltr4t3d}",    file:"pcap_mystery.pcap",   desc:"Analizza il traffico di rete e trova la flag." },
        ]
    },
];
