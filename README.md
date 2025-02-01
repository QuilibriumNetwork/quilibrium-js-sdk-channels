# Installation
This library is a stand-alone library that can be used in any project, and is currently used in the [Quorum Messenger app](https://github.com/quilibriumnetwork/quorum-desktop).

## Instructions

1. Install Node.js and npm (if not already installed)
   - Node.js version: `>=18.0.0` (LTS)
   - npm version: `>=8.0.0`

2. Install Rollup globally (if not already installed)
   ```bash
   npm install --global rollup
   yarn global add rollup # or use yarn
   ```

3. Install dependencies
   ```bash
   yarn
   ```

4. Build the library
   ```bash
   yarn build
   ```

5. Tell Yarn about this package
   ```bash
   yarn link
   ```

6. Use the library in your project
   ```bash
   yarn add @quilibrium/quilibrium-js-sdk-channels
   ```

# License

Copyright (c) 2025 Quilibrium Inc

See [LICENSE](LICENSE) for details.

