const toc = require('markdown-toc');

module.exports = function (string) {
    return toc.insert(string)
};