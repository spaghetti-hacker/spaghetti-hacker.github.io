/* ══════════════════════════════════════════
   challenges.js :: file di configurazione condiviso
   Importato da ctf.html e admin_flags.html
══════════════════════════════════════════ */
const CHALLENGES = [
    {
        cat: "REV",
        challenges: [
            { title:"Baby Rev",       diff:"easy",   pts:50,  flag:"7ca442e90fbe04d1d52da076f4383cf5e59bb8113b0ee72ec84f71dd5e5a33e6",        file:"hcf000",            desc:"Reversing for dummies." },
            { title:"sFunc",       diff:"med",   pts:100,  flag:"04e2b0d7d3159b6fe013687210aec7850da1f1b4555e16bb7bfb2e7a6234ea74",        file:"sw.txt",            desc:"Reversing della sFunc. La flag è: flag{...}. Al posto dei puntini scrivere la parola inglese che descrive la sFunc." },
        ]
    },
    {
        cat: "PWN",
        challenges: [
            { title:"Stack Overflow", diff:"easy",    pts:50, flag:"c6f98dd180bc4255b089c789c45c7708e3eef5e909c610a41e9b230cb5c95ad9",       file:"smash",      desc:"Buffer overflow classico su x86-64." },
            { title:"Smash The Stack For Fun And Profit", diff:"med",    pts:100, flag:"5d07a78c0349a26c535b3f44034b257afae3e8701ee41a39a2af16461b817380",       file:"smash2",      desc:"Buffer overflow classico su x86-64." },
        ]
    },
    {
        cat: "MAL",
        challenges: [
            { title:"Dropper",        diff:"med",    pts:150, flag:"282462e6de49e5c1e0b2d58a120a51c7c53c24783388ba2bb37b887f49bc0dcb",         file:"dropper",                    desc:"Analizza un dropper ELF. Trova la flag." },
        ]
    },
    {
        cat: "CRYPTO",
        challenges: [
            { title:"XOR Crypto",     diff:"easy",   pts:50,  flag:"2d838248a738c3c87345e5473c9c2f3a259689eb6676165cf14c5843f9fb8fe1",      file:"hr.txt",          desc:"Decrypt the Ciphertext." },
        ]
    },
    {
        cat: "FORENSICS",
        challenges: [
            { title:"PCAP Mystery",   diff:"easy",    pts:50, flag:"2be272137d271e45f39caaf5cd2ede54e8dc99517e044f28192c78d74187ae98",    file:"ch1.pcap",   desc:"Analizza il traffico di rete. La flag è: flag{...}" },
        ]
    },
];
