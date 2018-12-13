const fs = require('fs');

const plugins = [
    require('./pagebreak'),
    require('./toc'),
];

module.exports = function (file) {
    plugins.forEach((plugin) => {
        const contents = fs.readFileSync(file, 'utf8');
        const processed = plugin(contents);
        fs.writeFileSync(file, processed);
    });
};