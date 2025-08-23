/// <reference types="vitest" />
// Configure Vitest (https://vitest.dev/config/)
import {defineConfig} from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
    build: {
        lib: {
            entry: 'src/index.ts',
            formats: ['es'],
            fileName: (format) => `index.${format}.js`
        },
        rollupOptions: {
            external: ['fs', 'fs/promises', 'os', 'child_process', 'path', 'crypto'],
        },
        sourcemap: true,
        target: 'node22'
    },
    plugins: [dts()]
});
