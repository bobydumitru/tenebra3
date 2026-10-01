# TENEBRA Wallet Extension

Wallet browser non-custodial pentru DEX-ul TENEBRA.

## Instalare locală în Chrome sau Edge

1. Deschide `chrome://extensions` sau `edge://extensions`.
2. Activează **Developer mode**.
3. Alege **Load unpacked**.
4. Selectează folderul `wallet-extension`.
5. Deschide https://tenebra-network.com/tenebra-dex.html și reîncarcă pagina.
6. Apasă iconița TENEBRA Wallet, selectează fișierul `.tsc1` și introdu parola.
7. În DEX apasă **Verifică wallet-ul**.

## Ce verifică adaptorul

- rețeaua `TSC-1`;
- adresa publică a wallet-ului;
- semnătura Ristretto a unui mesaj fără fonduri;
- cheia și parola rămân în extensie, în memorie, doar pentru sesiunea curentă.

Extensia nu trimite fonduri la instalare și nu cere seed-ul în pagina web. Operațiile DEX vor fi activate după finalizarea și testarea metodei de aprobare pentru fiecare tranzacție.
