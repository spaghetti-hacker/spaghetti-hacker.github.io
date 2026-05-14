/* ══════════════════════════════════════════
   challenges.js — file di configurazione condiviso
   Importato da ctf.html e admin_flags.html
══════════════════════════════════════════ */
const CHALLENGES = [
    {
        cat: "REV",
        challenges: [
            { title:"Baby Rev",       diff:"easy",   pts:50,  flag:"7ca442e90fbe04d1d52da076f4383cf5e59bb8113b0ee72ec84f71dd5e5a33e6",        file:"hcf000",            desc:"Reversing for dummies" },
        ]
    },
    {
        cat: "PWN",
        challenges: [
            { title:"Stack Overflow", diff:"easy",    pts:50, flag:"c6f98dd180bc4255b089c789c45c7708e3eef5e909c610a41e9b230cb5c95ad9",       file:"smash",      desc:"Buffer overflow classico su x86-64" },
        ]
    },
    {
        cat: "MAL",
        challenges: [
            { title:"Dropper",        diff:"easy",    pts:50, flag:"282462e6de49e5c1e0b2d58a120a51c7c53c24783388ba2bb37b887f49bc0dcb",         file:"dropper",                    desc:"Analizza un dropper ELF. Trova la flag." },
        ]
    },
    {
        cat: "CRYPTO",
        challenges: [
            { title:"XOR Crypto",     diff:"easy",   pts:75,  flag:"",      file:"",          desc:"Ciphertext cifrato con XOR a chiave ripetuta di 4 byte." },
        ]
    },
    {
        cat: "FORENSICS",
        challenges: [
            { title:"PCAP Mystery",   diff:"easy",    pts:50, flag:"",    file:"",   desc:"Analizza il traffico di rete e trova la flag." },
        ]
    },
];
