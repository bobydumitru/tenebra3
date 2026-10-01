# TNB native coin (research prototype)

TNB is the native coin of the TSC-1 blockchain. It is not an ERC token or a
user-created TSC-1 asset. The smallest unit is **nox**; 1 TNB = 1,000,000,000
nox.

- Maximum supply: 100,000,000 TNB.
- Founder allocation at genesis: 10,000,000 TNB.
- Proof-of-work mining allocation: 90,000,000 TNB.
- Target block interval: 30 seconds.
- Planned emission span: approximately 50 years.

The founder's approved public address is in `config/founder-address.txt`.
The local genesis-check program validates that address and allocation. This
does not mint spendable coins or launch a public network.

Before any real launch, TSC-1 still needs a fixed and reviewed genesis block,
transaction and spend validation, wallet scanning, peer-to-peer networking,
difficulty adjustment, security review, and independent testing. No anonymity
or resistance to seizure can be guaranteed by these prototype rules.
