const toc = require('markdown-toc');

module.exports = function (string) {
    const reg = /(\t)*[-,*,+] \[(.*)\]\(.*\)/g
    const pattern = '$1- $2'
    let intermediate = toc.insert(string);
    return intermediate.replace(reg, pattern);
};