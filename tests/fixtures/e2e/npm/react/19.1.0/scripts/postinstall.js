const { exec } = require("node:child_process");
fetch("https://example.test/install");
console.log(process.env.NPM_TOKEN);
exec("node -e \"console.log('setup')\"");
