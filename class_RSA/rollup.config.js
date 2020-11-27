export default {
    input: 'src/index.js',
    output: [
        {
            file: 'index.cjs.js',
            format: 'cjs'
        },
        {
            file: 'index.esm.js',
            format: 'esm'
        }
    ],
    external: ['bigint-crypto-utils', 'bigint-conversion'] // <-- Suppresses warning when executing rollup (npx rollup -c)
    // We must tell rollup to use all IMPORTS as INTERNAL, like we have done for EXTERNAL
}
