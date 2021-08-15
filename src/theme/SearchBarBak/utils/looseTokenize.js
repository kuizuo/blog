// https://zhuanlan.zhihu.com/p/33335629
const singleMatchOfWord = /\w+|\p{Unified_Ideograph}/u;
export function looseTokenize(content) {
    const tokens = [];
    let start = 0;
    let text = content;
    while (text.length > 0) {
        const match = text.match(singleMatchOfWord);
        if (!match) {
            tokens.push(text);
            break;
        }
        if (match.index > 0) {
            tokens.push(text.substr(0, match.index));
        }
        tokens.push(match[0]);
        start += match.index + match[0].length;
        text = content.substr(start);
    }
    return tokens;
}
