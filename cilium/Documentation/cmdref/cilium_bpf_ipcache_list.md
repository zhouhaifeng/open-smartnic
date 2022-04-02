<!-- This file was autogenerated via cilium cmdref, do not edit manually-->

## cilium bpf ipcache list

List endpoint IPs (local and remote) and their corresponding security identities

### Synopsis

List endpoint IPs (local and remote) and their corresponding security identities.

Note that for Linux kernel versions between 4.11 and 4.15 inclusive, the native
LPM map type used for implementing this feature does not provide the ability to
walk / dump the entries, so on these kernel versions this tool will never
return any entries, even if entries exist in the map. You may instead run:
    cilium map get cilium_ipcache


```
cilium bpf ipcache list [flags]
```

### Options

```
  -h, --help            help for list
  -o, --output string   json| jsonpath='{}'
```

### Options inherited from parent commands

```
      --config string   config file (default is $HOME/.cilium.yaml)
  -D, --debug           Enable debug messages
  -H, --host string     URI to server-side API
```

### SEE ALSO

* [cilium bpf ipcache](../cilium_bpf_ipcache)	 - Manage the IPCache mappings for IP/CIDR <-> Identity
