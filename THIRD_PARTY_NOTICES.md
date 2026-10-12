# Third-party notices

The account/Calendar protocol was independently implemented using source review of the community CLI and Proton web client. The MCP transport pattern follows the neighboring local MCP projects. This repository does not vendor, execute, or distribute the community CLI or WebClients source.

Reference projects:

- `roman-16/proton-cli`, MIT, copyright (c) 2026 Roman. See the pinned reference in `docs/security-review.md`.
- `ProtonMail/WebClients`, the official source reference; consult its repository and Calendar application license for its terms. No WebClients source is copied into this repository.
- `openai/tunnel-client`, Apache-2.0. Its license and NOTICE are included in the separate tunnel container.

Runtime dependencies remain separate Go modules, pinned by `go.mod` and `go.sum`, including ProtonMail/go-srp, ProtonMail/gopenpgp, ProtonMail/go-crypto, emersion/go-ical, modelcontextprotocol/go-sdk, teambition/rrule-go, and Go x packages. Their upstream licenses apply. Go's module cache includes each dependency's source/license; review these when redistributing a build. These projects are not sponsors or endorsers of this MCP server.

The authentication tests reuse the public signed SRP modulus from ProtonMail/go-srp's test fixtures. The fixture is public protocol data, not an account credential or private key.

## ProtonMail/go-srp fixture license

The MIT License

Copyright (c) 2019 Proton Technologies AG

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
