<div align="center" markdown="1">

➡️ [Discord][discord] | [Installation Guide][toc-install] | [Usage Guide][usage-guide] ⬅️

<img src="pictures/rustscan.png" height=400px width=400px>

<!--<u>**The Modern Port Scanner.**</u>-->
**Fast, smart, effective.**

![Arch Linux package][badge-1] ![Built with Rust][badge-2] ![GitHub All Releases][badge-3] ![Crates.io][badge-4] ![Discord][badge-5] ![Actions][badge-6]

</div>

# 🤔 What is this?

![fast][speed-1]

The Modern Port Scanner. **Find ports quickly (3 seconds at its fastest)**. Run scripts through our scripting engine (Python, Lua, Shell supported).

# 🛠️ Installation

You can install RustScan's binary from our [releases page](https://github.com/RustScan/RustScan/releases).

We would prefer you to install with a package manager so it is tested and works for your system.

RustScan is in many repositories already. Install it with whatever tools you wish:

[![Packaging status](https://repology.org/badge/vertical-allrepos/rustscan.svg)](https://repology.org/project/rustscan/versions)

RustScan only officially supports Cargo installations, if you want to use that please install Rust and then `cargo install rustscan`

Example installations include:

MacOS:

```
  brew install rustscan
```

Arch:

```
  yay rustscan
```

# ✨ Features

- Scans all 65k ports in **3 seconds**.
- Full scripting engine support. Automatically pipe results into Nmap, or use our scripts (or write your own) to do whatever you want.
- Adaptive learning. RustScan improves the more you use it. No bloated machine learning here, just basic maths.
- The usuals you would expect. IPv6, CIDR, file input and more.
- Automatically pipes ports into Nmap.

## ‼️ Important Links

|         <!--Installation Guide-->          |          <!--Documentation-->          |       <!--Discord-->        |
| :----------------------------------------: | :------------------------------------: | :-------------------------: |
| :book: [Installation Guide][links-table-1] | :books: [Documentation][links-table-2] | :parrot: [Discord][discord] |

## 🙋 Table of Contents

- 📖 [Installation Guide][toc-install]
- 🐋 [Docker Usage][toc-docker-usage]
- 🦜 [Discord][discord]
- 🤸 [Usage][usage-1]

# 🔭 Why RustScan?

RustScan is a modern take on the port scanner. Sleek & fast. All while providing extensive extendability to you.

Not to mention RustScan uses Adaptive Learning to improve itself over time, making it the best port scanner for **you**.

## 🧋 Speed

![fast][speed-1]

Speed is guaranteed via RustScan. However, if you want to run a slow scan due to stealth, that is possible too.

Firstly, let's talk code.

We have tests that check to see if RustScan is significantly slower than the previous version. If it is, the continuous integration fails, and we can't commit code to master unless we make it faster.

[HyperFine][speed-2] is used to monitor RustScan's performance over time to answer the question, "Are we getting faster? Are we getting slower?".

Every pull request is reviewed by **one** person, but more often than not, **two** people review it. We test it manually and ensure the code doesn't negatively affect performance.

[Read more here][speed-3].

## ⚙️ Extensible

![scripts][extensible-1]

### _RustScan piping results into the custom Python script_

RustScan has a new scripting engine that allows anyone to write scripts in most languages. Python, Lua, and Shell are all supported.

Want to take your found ports and pipe them into Nmap for further analysis? That's possible. Want to run `smb-enum` if SMB is found open? Possible.

The possibilities are endless -- and you can write scripts in whatever language you feel comfortable with.

[Read more here][extensible-2].

## 🌊 Adaptive

![adaptive][adaptive-1]

### _RustScan automatically fine-tunes itself to match the host OS_

RustScan has a cool set of features called "Adaptive Learning". These features "learn" about the environment you are scanning and how _you_ use RustScan to **improve itself over time**.

We use this umbrella term for any feature that fits this criterion. The list constantly changes, so [check out our wiki for more information][adaptive-learning].

## 👩‍🦯 Accessible

![fast][accessible-1]

RustScan is one of the first penetration testing tools that aims to be entirely accessible.

[Most penetration testing tools are not accessible][accessible-2], which negatively affects the whole industry.

RustScan has continuous integration testing that aims to ensure it is accessible, and we are constantly working on ways to improve our accessibility and ensure _everyone_ can use RustScan.

# 🤸 Usage

We have two usage guides. [Basic Usage][usage-1] and [Things you may want to do][usage-2].

We also have documentation about our config file [here][config-file-here].

# 🎪 Community

[Contributing][community-1] Read this to learn how.

## Contributors ✨

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->

[![All Contributors](https://img.shields.io/badge/all_contributors-26-orange.svg?style=flat-square)](#contributors-)

<!-- ALL-CONTRIBUTORS-BADGE:END -->

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://skerritt.blog"><img src="https://avatars3.githubusercontent.com/u/10378052?v=4" width="100px;" alt=""/><br /><sub><b>Bee</b></sub></a><br /><a href="#infra-beeskerritt" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/RustScan/RustScan/commits?author=beeskerritt" title="Tests">⚠️</a> <a href="https://github.com/RustScan/RustScan/commits?author=beesan" title="Code">💻</a> <a href="#design-beeskerritt" title="Design">🎨</a></td>
    <td align="center"><a href="https://sakiir.ovh"><img src="https://avatars1.githubusercontent.com/u/9950578?v=4" width="100px;" alt=""/><br /><sub><b>SakiiR</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=SakiiR" title="Code">💻</a> <a href="https://github.com/RustScan/RustScan/issues?q=author%3ASakiiR" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/smackhack"><img src="https://avatars2.githubusercontent.com/u/48143394?v=4" width="100px;" alt=""/><br /><sub><b>smackhack</b></sub></a><br /><a href="#ideas-smackhack" title="Ideas, Planning, & Feedback">🤔</a> <a href="#example-smackhack" title="Examples">💡</a></td>
    <td align="center"><a href="http://bernardoamc.github.io/"><img src="https://avatars0.githubusercontent.com/u/428984?v=4" width="100px;" alt=""/><br /><sub><b>Bernardo Araujo</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=bernardoamc" title="Code">💻</a> <a href="https://github.com/RustScan/RustScan/issues?q=author%3Abernardoamc" title="Bug reports">🐛</a> <a href="#design-bernardoamc" title="Design">🎨</a></td>
    <td align="center"><a href="https://github.com/Isona"><img src="https://avatars2.githubusercontent.com/u/11759523?v=4" width="100px;" alt=""/><br /><sub><b>Izzy Whistlecroft</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/issues?q=author%3AIsona" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://imlonghao.com"><img src="https://avatars1.githubusercontent.com/u/4951333?v=4" width="100px;" alt=""/><br /><sub><b>imlonghao</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/issues?q=author%3Aimlonghao" title="Bug reports">🐛</a> <a href="#maintenance-imlonghao" title="Maintenance">🚧</a></td>
    <td align="center"><a href="https://github.com/royharoush"><img src="https://avatars3.githubusercontent.com/u/8113056?v=4" width="100px;" alt=""/><br /><sub><b>royharoush</b></sub></a><br /><a href="#ideas-royharoush" title="Ideas, Planning, & Feedback">🤔</a> <a href="#design-royharoush" title="Design">🎨</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/Atul9"><img src="https://avatars1.githubusercontent.com/u/3390330?v=4" width="100px;" alt=""/><br /><sub><b>Atul Bhosale</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=Atul9" title="Code">💻</a></td>
    <td align="center"><a href="https://tgotwig.dev"><img src="https://avatars0.githubusercontent.com/u/30773779?v=4" width="100px;" alt=""/><br /><sub><b>Thomas Gotwig</b></sub></a><br /><a href="#platform-TGotwig" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="https://github.com/remigourdon"><img src="https://avatars3.githubusercontent.com/u/2874133?v=4" width="100px;" alt=""/><br /><sub><b>Rémi Gourdon</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=remigourdon" title="Documentation">📖</a> <a href="https://github.com/RustScan/RustScan/commits?author=remigourdon" title="Code">💻</a></td>
    <td align="center"><a href="https://cmnatic.co.uk"><img src="https://avatars3.githubusercontent.com/u/4163116?v=4" width="100px;" alt=""/><br /><sub><b>Ben (CMNatic)</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=cmnatic" title="Code">💻</a> <a href="https://github.com/RustScan/RustScan/commits?author=cmnatic" title="Documentation">📖</a> <a href="#design-cmnatic" title="Design">🎨</a></td>
    <td align="center"><a href="https://github.com/Ferryistaken"><img src="https://avatars3.githubusercontent.com/u/47927670?v=4" width="100px;" alt=""/><br /><sub><b>Alessandro Ferrari</b></sub></a><br /><a href="#content-Ferryistaken" title="Content">🖋</a></td>
    <td align="center"><a href="https://github.com/Phenomite"><img src="https://avatars2.githubusercontent.com/u/8285537?v=4" width="100px;" alt=""/><br /><sub><b>Phenomite</b></sub></a><br /><a href="#content-Phenomite" title="Content">🖋</a></td>
    <td align="center"><a href="https://supersandro.de/"><img src="https://avatars2.githubusercontent.com/u/7258858?v=4" width="100px;" alt=""/><br /><sub><b>Sandro</b></sub></a><br /><a href="#content-SuperSandro2000" title="Content">🖋</a> <a href="https://github.com/RustScan/RustScan/issues?q=author%3ASuperSandro2000" title="Bug reports">🐛</a> <a href="https://github.com/RustScan/RustScan/commits?author=SuperSandro2000" title="Code">💻</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://swag.lgbt"><img src="https://avatars2.githubusercontent.com/u/25358963?v=4" width="100px;" alt=""/><br /><sub><b>Cass</b></sub></a><br /><a href="#platform-caass" title="Packaging/porting to new platform">📦</a> <a href="https://github.com/RustScan/RustScan/commits?author=caass" title="Code">💻</a> <a href="https://github.com/RustScan/RustScan/issues?q=author%3Acaass" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://github.com/niklasmohrin"><img src="https://avatars0.githubusercontent.com/u/47574893?v=4" width="100px;" alt=""/><br /><sub><b>Niklas Mohrin</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=niklasmohrin" title="Documentation">📖</a> <a href="https://github.com/RustScan/RustScan/commits?author=niklasmohrin" title="Code">💻</a> <a href="https://github.com/RustScan/RustScan/issues?q=author%3Aniklasmohrin" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://liberapay.com/Artem4/"><img src="https://avatars0.githubusercontent.com/u/5614476?v=4" width="100px;" alt=""/><br /><sub><b>Artem Polishchuk</b></sub></a><br /><a href="#platform-tim77" title="Packaging/porting to new platform">📦</a></td>
    <td align="center"><a href="https://github.com/buermarc"><img src="https://avatars2.githubusercontent.com/u/44375277?v=4" width="100px;" alt=""/><br /><sub><b>buermarc</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=buermarc" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/bergabman"><img src="https://avatars1.githubusercontent.com/u/44554109?v=4" width="100px;" alt=""/><br /><sub><b>bergabman</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=bergabman" title="Code">💻</a> <a href="https://github.com/RustScan/RustScan/issues?q=author%3Abergabman" title="Bug reports">🐛</a> <a href="#design-bergabman" title="Design">🎨</a></td>
    <td align="center"><a href="https://github.com/dmitris"><img src="https://avatars0.githubusercontent.com/u/31205?v=4" width="100px;" alt=""/><br /><sub><b>Dmitry Savintsev</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=dmitris" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/bofh69"><img src="https://avatars3.githubusercontent.com/u/1444315?v=4" width="100px;" alt=""/><br /><sub><b>Sebastian Andersson</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=bofh69" title="Code">💻</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://github.com/mattcorbin"><img src="https://avatars3.githubusercontent.com/u/6537765?v=4" width="100px;" alt=""/><br /><sub><b>Matt Corbin</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=mattcorbin" title="Code">💻</a></td>
    <td align="center"><a href="http://rootsploit.com"><img src="https://avatars2.githubusercontent.com/u/67270834?v=4" width="100px;" alt=""/><br /><sub><b>RootSploit</b></sub></a><br /><a href="#blog-rootsploit" title="Blogposts">📝</a></td>
    <td align="center"><a href="https://github.com/eiffel-fl"><img src="https://avatars2.githubusercontent.com/u/12171754?v=4" width="100px;" alt=""/><br /><sub><b>eiffel-fl</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=eiffel-fl" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/u5surf"><img src="https://avatars1.githubusercontent.com/u/14180225?v=4" width="100px;" alt=""/><br /><sub><b>Y.Horie</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=u5surf" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/okrplay"><img src="https://avatars3.githubusercontent.com/u/32576280?v=4" width="100px;" alt=""/><br /><sub><b>Oskar</b></sub></a><br /><a href="https://github.com/RustScan/RustScan/commits?author=okrplay" title="Code">💻</a> <a href="https://github.com/RustScan/RustScan/commits?author=okrplay" title="Tests">⚠️</a></td>
  </tr>
</table>

<!-- markdownlint-enable -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

<!--Links-->

[Docker]: https://hub.docker.com/r/cmnatic/rustscan "This is the recommended distribution of rustscan"
[kali]: https://github.com/RustScan/RustScan/wiki/Installation-Guide#%EF%B8%8F-debian--kali "Read the install guide"
[Kali/Debian]: https://github.com/RustScan/RustScan/releases "Kali Debian"
[Arch-Linux]: https://archlinux.org/packages/extra/x86_64/rustscan/ "Arch Linux installation of Rustscan"
[Homebrew]: https://formulae.brew.sh/formula/rustscan "Homebrew install of Rustscan"
[usage-1]: https://github.com/RustScan/RustScan/wiki/Usage "Basic Usage of Rustscan"
[usage-0]: https://github.com/RustScan/RustScan/wiki/Installation-Guide#docker-whale "Use Docker Rustscan"
[config-file-here]: https://github.com/RustScan/RustScan/wiki/Config-File "RustScan Configuration File"
[usage-2]: https://github.com/RustScan/RustScan/wiki/Things-you-may-want-to-do-with-RustScan-but-don't-understand-how "Things you may want to do with rustscan but don't know how"
[community-1]: https://github.com/RustScan/RustScan/wiki/Contributing "Learn how to contribute"
[distributions-1]: https://software.opensuse.org/package/rustscan?search_term=rustscan "Open Suse rustscan distribution"
[distributions-2]: https://copr.fedorainfracloud.org/coprs/atim/rustscan/ "Rustscan in Fedora"
[repology-1]: https://repology.org/project/rustscan/versions "Packaging Status"
[install-1]: https://github.com/RustScan/RustScan/wiki/Installation-Guide "Installation guide"
[accessible-2]: https://bees.substack.com/p/making-hacking-accessible "Making Hacking Accessible"
[extensible-2]: https://github.com/RustScan/RustScan/wiki/RustScan-Scripting-Engine "Scripting Engine"
[speed-2]: https://github.com/sharkdp/hyperfine "Hyperfine"
[speed-3]: https://github.com/RustScan/RustScan/wiki/Increasing-Speed-&-Accuracy "Increasing Speed & Accuracy"
[toc-community]: https://github.com/RustScan/RustScan#-community "Community"
[links-table-1]: https://github.com/RustScan/RustScan#-full-installation-guide "Full installation guide"
[links-table-2]: https://github.com/bee-san/RustScan/wiki "Rustscan"
[discord]: http://discord.skerritt.blog "Discord blog"
[toc-install]: https://github.com/RustScan/RustScan/wiki/Installation-Guide "Installation Guide Wiki"
[toc-docker-usage]: https://github.com/RustScan/RustScan/wiki/Installation-Guide#docker- "Docker Installation Guide Wiki"
[usage-guide]: https://github.com/RustScan/RustScan#-usage
[adaptive-learning]: https://github.com/RustScan/RustScan/wiki/Adaptive-Learning "Adaptive Learning"

<!--Pictures-->

[DockerPic]: https://github.com/RustScan/RustScan/blob/master/pictures/docker.png?raw=true "Docker install"
[Kali1]: https://github.com/RustScan/RustScan/blob/master/pictures/kali.png?raw=true "Kali Picture"
[Arch]: https://github.com/RustScan/RustScan/blob/master/pictures/arch.png?raw=true "Arch Linux"
[Apple]: https://raw.githubusercontent.com/RustScan/RustScan/master/pictures/apple.png?size "Apple"
[rustscan-svg]: https://repology.org/badge/vertical-allrepos/rustscan.svg "Picture of rustscan repology"
[accessible-1]: pictures/accessible.gif "Fast"
[adaptive-1]: pictures/adaptive.gif "Adaptive"
[extensible-1]: pictures/scripts.gif "Scripts"
[speed-1]: pictures/fast.gif "Speed"
[badge-1]: https://img.shields.io/archlinux/v/extra/x86_64/rustscan?style=plastic&logo=archlinux&link=https%3A%2F%2Farchlinux.org%2Fpackages%2Fextra%2Fx86_64%2Frustscan%2F
[badge-2]: https://img.shields.io/badge/Built%20with-Rust-Purple
[badge-3]: https://img.shields.io/github/downloads/rustscan/rustscan/total?label=GitHub%20Downloads
[badge-4]: https://img.shields.io/crates/d/rustscan?label=Cargo%20Downloads
[badge-5]: https://img.shields.io/discord/754001738184392704
[badge-6]: https://github.com/RustScan/RustScan/actions/workflows/build.yml/badge.svg?branch=master
