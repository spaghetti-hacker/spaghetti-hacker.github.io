/* ══════════════════════════════════════════
   challenges.js — file di configurazione condiviso
   Importato da ctf.html e admin_flags.html
══════════════════════════════════════════ */
const CHALLENGES = [
    {
        cat: "REV",
        challenges: [
            { title:"Baby Rev",       diff:"easy",   pts:50,  flag:"d26b71303eebb857561a2e123debd6006bbe437b30a0fb04d25810c568896536",        file:"baby_rev",            desc:"Crackme con password offuscata tramite XOR." },
        ]
    },
    {
        cat: "PWN",
        challenges: [
            { title:"Stack Overflow", diff:"easy",    pts:50, flag:"flag{r1p_r3tu4rn_addr3ss}",       file:"stack_overflow",      desc:"Buffer overflow classico su x86-64. Reindirizza il flusso." },
        ]
    },
    {
        cat: "MAL",
        challenges: [
            { title:"Dropper",        diff:"easy",    pts:50, flag:"flag{dr0pp3r_1n_m3m0ry}",         file:"",                    desc:"Analizza un dropper ELF che scarica e lancia un payload in memoria. Trova IoC." },
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
            { title:"PCAP Mystery",   diff:"easy",    pts:50, flag:"flag{pcap_fl4g_3xf1ltr4t3d}",    file:"pcap_mystery.pcap",   desc:"Analizza il traffico di rete e trova la flag." },
        ]
    },
];
