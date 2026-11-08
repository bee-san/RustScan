# Exporting Nmap Reports

RustScan pipes the ports it finds into Nmap, and anything after `--` on the
command line is appended to that Nmap invocation. That makes it easy to keep
Nmap's own reports (XML, greppable, normal output) with `-oA` / `-oX` / `-oN` /
`-oG`.

## Local runs

Point Nmap's output flag at a path on your machine:

```sh
rustscan -a 10.1.1.2 -- -oA ./report
```

This writes `report.nmap`, `report.xml` and `report.gnmap` next to where you
ran the command.

## Docker runs

The container cannot see your filesystem unless you mount a directory into it.
Create a directory for the reports and give the container somewhere to write:

```console
mkdir -p /report
chmod 777 /report
```

Then mount it with `-v` and tell Nmap (not RustScan) to write inside the
mount. The path after `-oA` is the path *inside the container* (`/output` in
this example), while the files land in `/report` on your machine:

```console
docker run -it --rm --name rustscan -v /report:/output rustscan/rustscan:2.1.1 -a 10.1.1.2 -- -oA /output/xml
```

Notes:

- `-v /report:/output` means "make the host's `/report` appear as `/output`
  inside the container". If you create the directory somewhere else (for
  example under `$HOME`), adjust the left side of the `-v` flag; the `-oA`
  path must still point under `/output`.
- Everything after `--` is passed to Nmap, so any Nmap output flag works
  (`-oN`, `-oX`, `-oG`, `-oA`), as do the usual scan flags such as `-A` or
  `-sV`.
- If Docker itself was installed through `snap`, its confinement can block
  the write even when the mount looks right; an `apt`-installed Docker does
  not have that problem.

## Troubleshooting

- **Empty or missing report files**: double-check that the `-oA` path is
  inside the mounted directory (`/output/...` in the example above). A path
  outside the mount is written inside the container's filesystem and thrown
  away with `--rm`.
- **Permission errors**: the Nmap process inside the container must be able to
  write to the mounted directory; that is what the `chmod` step above is for.
