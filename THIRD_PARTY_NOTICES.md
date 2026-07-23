# Third-party software

WiFiCatcher is released under the MIT License (see [LICENSE](LICENSE)). That
license covers **WiFiCatcher's own code only**. The project also relies on
third-party software, in two different ways described below. In both cases the
third-party software stays under its own license and belongs to its own authors.

## Tools run as separate programs

These tools are **not** part of WiFiCatcher and are **not** included in this
repository. You install them yourself, and WiFiCatcher runs them as separate
processes over the command line. Running a program at arm's length like this
does not make WiFiCatcher a derivative work of it, so their licenses (including
the GPL ones) do not extend to WiFiCatcher's own code. They keep their own terms.

| Tool | Project | License |
| --- | --- | --- |
| `airodump-ng`, `aireplay-ng`, `airmon-ng` | [aircrack-ng](https://www.aircrack-ng.org/) | GPL-2.0 |
| `tshark` | [Wireshark](https://www.wireshark.org/) | GPL-2.0 |
| `wpa_supplicant` | [wpa_supplicant](https://w1.fi/wpa_supplicant/) | BSD-3-Clause |

## Bundled components

These components are vendored (copied) into this repository so some features work
out of the box. Each keeps its own license and copyright; WiFiCatcher's MIT
license does not apply to them. Their license notices are preserved next to the
files.

| Component | Location | Author | License |
| --- | --- | --- | --- |
| EAP_buster | `WiFiCatcher/vendor/EAP_buster/` | [BlackArrow](https://github.com/blackarrowsec/EAP_buster) (Miguel Amat) | MIT |
| Cytoscape.js | `WiFiCatcher/web/static/vendor/cytoscape.min.js` | [The Cytoscape Consortium](https://js.cytoscape.org/) | MIT |
| fCoSE layout (`cytoscape-fcose`, `cose-base`, `layout-base`) | `WiFiCatcher/web/static/vendor/` | [i-Vis Research Lab, Bilkent University](https://github.com/iVis-at-Bilkent) | MIT / Apache-2.0 |

For the exact terms, see each component's own license notice (for example
`WiFiCatcher/vendor/EAP_buster/LICENSE`) or the license header inside the file.
