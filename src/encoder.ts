let TextEncoder;
if (typeof globalThis.TextEncoder === 'undefined') {
    TextEncoder = require('text-encoding').TextEncoder;
} else {
    TextEncoder = globalThis.TextEncoder;
}

export default TextEncoder;
