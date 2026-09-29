# Commercial License for Agentic Privacy Guard

Copyright (C) 2026 NERVOSYS. All rights reserved.

## Dual Licensing

Agentic Privacy Guard (APG) is available under two licensing options:

### 1. GNU Affero General Public License v3 (AGPL-3.0-or-later)

The default license for APG is the **GNU Affero General Public License v3**. Under this license:

- You may freely use, copy, modify, and distribute the software.
- If you modify the software and make it available over a network (e.g., as a web service), you **must** make the complete source code of your modified version available to users of that service.
- Any derivative works must also be licensed under the AGPL v3.
- Full text: [LICENSE](LICENSE)

Note that the network clause has real reach for a cryptographic tool: embedding
APG in a service that encrypts, signs, or verifies data for remote users, or
exposing it to agents through a hosted MCP endpoint, makes that service a
derivative work, and the AGPL's source-disclosure obligation applies to it.

### 2. Commercial License

If the AGPL requirements are incompatible with your use case — for example, if you want to:

- Integrate APG into proprietary/closed-source software or agent platforms
- Embed it in a shipped product, appliance, firmware image, or hardware device
- Distribute APG without disclosing your source code
- Offer APG as part of a hosted/SaaS service without AGPL obligations
- Use the software under terms that do not require network-use disclosure
- Receive dedicated support, warranty, or indemnification

Then a **commercial license** is available from NERVOSYS.

APG links [IronCrypto](https://github.com/nervosys/IronCrypto), which is
dual-licensed on the same terms. A commercial APG deployment that avoids AGPL
obligations also requires commercial terms for IronCrypto; NERVOSYS can provide
both under one agreement.

## Obtaining a Commercial License

For commercial licensing inquiries, please contact:

- **Email**: licensing@nervosys.ai
- **GitHub**: [github.com/nervosys](https://github.com/nervosys)

Commercial licenses are available with flexible terms tailored to your needs, including per-seat, per-deployment, and enterprise-wide options.

## What a License Does Not Cover

Neither license is a statement about cryptographic assurance. In particular:

- **No FIPS validation.** Neither APG nor IronCrypto holds a CMVP certificate, and a commercial license does not confer one. Hardware-backed keys use whatever validation the external PKCS#11 module has; APG does not inherit or extend it. See [docs/HARDWARE.md](docs/HARDWARE.md).
- **No security audit.** The APG protocol and implementation have not been independently reviewed by cryptographers. See [SECURITY.md](SECURITY.md).
- **No export classification.** Licensing does not determine export-control obligations for encryption software. Obtain your own advice before distributing APG across borders or to restricted parties.
- **Warranty.** The AGPL version is provided without warranty, as stated in the licence. Warranty and indemnification terms, where offered, are set out in the commercial agreement rather than here.

## Contributor License Agreement (CLA)

All contributors must agree to the [Contributor License Agreement](CLA.md) before their contributions can be accepted. By submitting a pull request, you agree that your contributions may be distributed under both the AGPL v3 and commercial licenses. This enables the dual-licensing model to work for all users.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
