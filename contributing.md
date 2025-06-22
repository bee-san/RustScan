Howdy, Space Cow-Person 🤠🌌

RustScan is always looking for contributors. Whether that's spelling mistakes or major changes, your help is **wanted** and welcomed here.

Before contributing, read our [code of conduct](https://github.com/RustScan/RustScan/blob/master/CODE_OF_CONDUCT.md).

TL;DR if you abuse members of our community you will be **perma-banned** with no chance to get unbanned. No warnings either. 🤗

RustScan has 2 major labels for GitHub issues you should look at:

- Good First issue
  These are issues for newcomers to open source!
  [https://github.com/RustScan/RustScan/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22](https://github.com/RustScan/RustScan/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
- Help wanted
  These are issues that aren't really for newcomers, but we could still do with help!
  [https://github.com/RustScan/RustScan/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22+label%3A%22help+wanted%22](https://github.com/RustScan/RustScan/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22+label%3A%22help+wanted%22)

If you want to, solve the issue or comment on the issue for help.

The flow for contributing to open source software is:

- Fork the repo
- Make changes
- Pull request to the repo

And then comment on the issue that you've done.

RustScan also has some `// TODO`'s in the codebase, which are meant more for the core team but we would welcome help with these issues.

If you have any feature suggestions or bugs, leave a GitHub issue. We welcome any and all support :D

## Rewarding you

I cannot pay you :-( But, I can place your GitHub profile on the README under `#Contributors` as a thank you! :)

## Contributing development environment

To ease contribution to RustScan, you can use the `contributing.Dockerfile` to create a Docker image ready to build and play with RustScan.
To build it you just need to run:

```bash
you@home:~/RustScan$ docker build -t rustscan_contributing -f contributing.Dockerfile
```

Then you need to run the container with a volume so it can access, _with read and write permissions_, to RustScan files:

```bash
you@home:~/RustScan$ docker run -ti --rm -v "$PWD":/rustscan -w /rustscan rustscan_contributing bash
```

You can now modify RustScan files with your favorite editor, once you want to compile and test your modifications, type the following in the container prompt:

```bash
root@container:/rustscan# cargo build
```

You are now ready to use RustScan:

```bash
root@container:/rustscan# cargo run -- -b 2000 -t 5000 -a 127.0.0.1
```

You can also format, lint with `clippy` and test the code with the following commands:

```bash
root@container:/rustscan# cargo fmt
root@container:/rustscan# cargo clippy
root@container:/rustscan# cargo test
```
