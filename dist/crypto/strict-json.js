export function strictJson(text) {
    // JSON.parse validates the grammar; the walk retains the source tokens it normally discards.
    const result = JSON.parse(text);
    const tokens = text.match(/"(?:[^"\\]|\\.)*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\]:,]/gs);
    let at = 0;
    const string = (token) => {
        const value = JSON.parse(token);
        for (let i = 0; i < value.length; i++) {
            const unit = value.charCodeAt(i);
            if (unit >= 0xd800 && unit <= 0xdbff) {
                const next = value.charCodeAt(++i);
                if (!(next >= 0xdc00 && next <= 0xdfff))
                    throw new Error('Unpaired surrogate');
            }
            else if (unit >= 0xdc00 && unit <= 0xdfff)
                throw new Error('Unpaired surrogate');
        }
        return value;
    };
    const walk = (root = false) => {
        const token = tokens[at++];
        if (token === '{') {
            const names = new Set();
            while (tokens[at] !== '}') {
                const name = string(tokens[at++]);
                if (names.has(name))
                    throw new Error('Duplicate member');
                names.add(name);
                at++;
                if (root && name === 'updated_at' && !/^(?:0|[1-9]\d*)$/.test(tokens[at]))
                    throw new Error('Invalid updated_at');
                walk();
                if (tokens[at] !== ',')
                    break;
                at++;
            }
            at++;
        }
        else if (token === '[') {
            while (tokens[at] !== ']') {
                walk();
                if (tokens[at] !== ',')
                    break;
                at++;
            }
            at++;
        }
        else if (token.startsWith('"'))
            string(token);
    };
    walk(true);
    return result;
}
//# sourceMappingURL=strict-json.js.map