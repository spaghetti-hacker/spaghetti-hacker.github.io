/* ══════════════════════════════════════════
   challenges.js :: file di configurazione condiviso
   Importato da ctf.html e admin_flags.html
══════════════════════════════════════════ */
const CHALLENGES = [
    {
        cat: "REVERSE",
        challenges: [
            { title:"Baby Rev",       diff:"easy",   pts:50,  flag:"7ca442e90fbe04d1d52da076f4383cf5e59bb8113b0ee72ec84f71dd5e5a33e6",        file:"hcf000",            desc:"Reversing for dummies. Trova la flag nel file. Tool consigliati: [file, string]." },
            { title:"sFunc",       diff:"med",   pts:100,  flag:"04e2b0d7d3159b6fe013687210aec7850da1f1b4555e16bb7bfb2e7a6234ea74",        file:"sw.txt",            desc:"Reversing della sFunc. Cerca di capire cosa fa la funzione. La flag è: flag{cosa fa la funzione in Inglese}." },
            { title:"Bypass Me",       diff:"med",   pts:100,  flag:"8816ef83bbdf2c1e8f9bdd2216935d95708cd15baeb649763912020317cd3519",        file:"bypassme.bin",            desc:"Prova a bypassare il controllo sulla password. Tool consigliati: [radare2, gdb]." },
        ]
    },
    {
        cat: "PWN",
        challenges: [
            { title:"Stack Overflow", diff:"easy",    pts:50, flag:"c6f98dd180bc4255b089c789c45c7708e3eef5e909c610a41e9b230cb5c95ad9",       file:"smash",      desc:"Buffer overflow classico su x86-64. Tool consigliati: [radare2, gdb]." },
            { title:"Heap Overflow", diff:"easy",    pts:50, flag:"d3a2d7cbb1deb0e6a6cf5bd011ab3f071c42df4a5bdec3b4fceb7925bd8d14ce",       file:"heap",      desc:"Heap overflow classico su x86-64. Tool consigliati: [radare2, gdb]." },
            { title:"Smash The Stack", diff:"med",    pts:100, flag:"5d07a78c0349a26c535b3f44034b257afae3e8701ee41a39a2af16461b817380",       file:"smash2",      desc:"Buffer overflow classico su x86-64. Tool consigliati: [radare2, gdb]." },
        ]
    },
    {
        cat: "MALWARE",
        challenges: [
            { title:"Dropper Easy",        diff:"easy",    pts:50, flag:"b46c3d8f7a6e1e82b2d1acb7cad69622cb8825ffa5ca9e26440d9e25c4f2d130",         file:"dropper_easy",                    desc:"Analizza un dropper ELF. Trova l'IP del Command & Control. La flag è: flag{IP_C2}. Tool consigliati: [file, radare2, gdb]." },
            { title:"Dropper",        diff:"med",    pts:150, flag:"282462e6de49e5c1e0b2d58a120a51c7c53c24783388ba2bb37b887f49bc0dcb",         file:"dropper",                    desc:"Analizza un dropper ELF. Trova la flag. Tool consigliati: [file, radare2, gdb]." },
            { title:"Loader",        diff:"med",    pts:150, flag:"6539942db0e8209fa3d16f8b31e0ef196f20ff2793a522661619d9b3f8eabaf5",         file:"loader",                    desc:"Analizza un loader ELF. Trova la flag. Tool consigliati: [file, radare2, gdb]." },
        ]
    },
    {
        cat: "CRYPTO",
        challenges: [
            { title:"XOR Crypto",     diff:"easy",   pts:50,  flag:"69e1ba6e2fd49d23c88269cba0180050134a63342e360c0a03112921cfe86129",      file:"xor.txt",          desc:"Decrypt the Ciphertext. Tool online consigliato: [CyberChef]." },
            { title:"ASCII Crypto",     diff:"easy",   pts:50,  flag:"2d838248a738c3c87345e5473c9c2f3a259689eb6676165cf14c5843f9fb8fe1",      file:"hr.txt",          desc:"Decrypt the Ciphertext. Tool online consigliato: [CyberChef]." },
            { title:"Hash Crack",     diff:"med",   pts:100,  flag:"38529cec1f30394bcb1877071164ebec10e25cda6e4ca96dd534abd529612704",      file:"hashcrack",          desc:"Crack the Hash. Tool online consigliato: [CrackStation]." },
        ]
    },
    {
        cat: "GENERAL",
        challenges: [
            { title:"PCAP FTP",   diff:"easy",    pts:50, flag:"2be272137d271e45f39caaf5cd2ede54e8dc99517e044f28192c78d74187ae98",    file:"ch1.pcap",   desc:"Analizza il traffico di rete. La flag è: flag{password}. Tool consigliato: [Wireshark]." },
            { title:"PCAP Telnet",   diff:"easy",    pts:50, flag:"c17beda8c96140db5cf5d7609224b06b0c465909abb0d3f58e53714bfd46bf10",    file:"ch2.pcap",   desc:"Analizza il traffico di rete. La flag è: flag{password}. Tool consigliato: [Wireshark]." },
        ]
    },
];
