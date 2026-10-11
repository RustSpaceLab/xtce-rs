# xtce-cli

The `xtce` command: inspect an XTCE definition and decode a CCSDS stream against it.

```console
$ xtce info mission.xml                      # what it contains, and what cannot be decoded
$ xtce decode mission.xml downlink.dat       # values, as a table or as JSON lines
$ xtce decode mission.xml downlink.dat --param 'ADGPSPOS*'
```

`--param` takes a glob, and a value matching nothing in the definition is an error naming the
nearest parameter rather than an empty report.

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
