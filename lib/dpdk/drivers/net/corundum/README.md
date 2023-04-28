# DPDK PMD Driver for Corundum

Based on the [dpdk-corundum](https://github.com/xinyu-yang/dpdk-corundum).

## Install
Downloading `dpdk-20.11` from http://core.dpdk.org/download/ , and uncompress it into `dpdk-20.11/`.

Cloning this repository into `./dpdk-20.11/drivers/net/mqnic`:
```bash
git clone https://github.com/xinyu-yang/dpdk-corundum.git ./dpdk-20.11/drivers/net/mqnic
```

Then, replacing `dpdk-20.11/rte_config.h` with `replacement/rte_config.h`, replacing `dpdk-20.11/drivers/net/meson.build` with `replacement/meson.build`.

After that, compiling dpdk.



# Reference

[1] https://www.github.com/corundum/corundum/

[2] https://www.dpdk.org
