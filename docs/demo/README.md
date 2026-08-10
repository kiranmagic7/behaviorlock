# Inert demo recording

`scripts/demo-inert.sh` is the canonical 30-second product demonstration. It builds the local CLI, replays two hand-written offline traces, validates both evidence companions, renders the observed difference, and removes its temporary files. It does not contact npm, execute a package, or claim a real incident detection.

Run it directly:

```sh
./scripts/demo-inert.sh
```

Create a reproducible asciinema source recording:

```sh
./scripts/record-inert-demo.sh behaviorlock-inert-demo.cast
```

Review the cast for package-controlled text, local paths, terminal identifiers, and timing before sharing it. Recording does not authorize publication or promotion.
