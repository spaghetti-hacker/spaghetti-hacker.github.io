/* ══════════════════════════════════════════
   challenges.js — file di configurazione condiviso
   Importato da ctf.html e admin_flags.html
══════════════════════════════════════════ */
const CHALLENGES = [
    {
        cat: "REV",
        challenges: [
            { title:"Baby Rev",       diff:"easy",   pts:50,  flag:"80ee4f917a5e03e55725742a8aa7c2e032c3139e2be93ebaf47e1551f750587b",        file:"hcf000",            desc:"Reversing for dummies" },
        ]
    },
    {
        cat: "PWN",
        challenges: [
            { title:"Stack Overflow", diff:"easy",    pts:50, flag:"b4a4b21904129db00ece35af5810902f4d208e1283e0325936b77ee680e6799d",       file:"smash",      desc:"Buffer overflow classico su x86-64" },
        ]
    },
    {
        cat: "MAL",
        challenges: [
            { title:"Dropper",        diff:"easy",    pts:50, flag:"154f3443154a8dc86d7fcd6a84e4f901539c94d7b761a111639bf88dc65f5cab",         file:"dropper",                    desc:"Analizza un dropper ELF. Trova la flag." },
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
