const regex = /<!--[ \t]*break[ \t]*-->\n[<div style="page\-break\-after: always;"><\/div>\n]*/g;
const style =
`<!-- break -->
<div style="page-break-after: always;"></div>

`;

module.exports = function (string) {
    return string.replace(regex, style);
};