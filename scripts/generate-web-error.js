const fs = require('fs');
const path = require('path');

const content = `throw new Error("react-native-super-crypto does not support web/Next.js projects. Use only in React Native.");\n`;
fs.writeFileSync(path.join(__dirname, '../lib/web.js'), content);
