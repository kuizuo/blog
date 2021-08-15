export function simpleTemplate(template, params) {
    return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (raw, keyword) => {
        if (Object.prototype.hasOwnProperty.call(params, keyword)) {
            return String(params[keyword]);
        }
        return raw;
    });
}
