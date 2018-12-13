const markdownpdf = require('markdown-pdf');
const path = require('path')

const file = path.resolve('./source.md');

require('./preprocessing')(file);

// Options
const options = {
    remarkable: {
        breaks: false,
        html: true,
    }
}

markdownpdf(options)
    .from(file)
    .to(`./out/document-${new Date().toISOString()}.pdf`,
        () => (console.log("Build finished"))
    );