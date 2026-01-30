import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'
import path from 'path'

// See https://vitejs.dev/config/
export default defineConfig({
	plugins: [
		tailwindcss(),
		vue(),
	],
	resolve: {
		alias: {
			'@': path.resolve(__dirname, 'src'),
		},
	},
	publicDir: 'icons',
	clearScreen: false,
	envPrefix: ['VITE_', 'TAURI_'],
	server: {
		port: 1420,
		strictPort: true,
		fs: {
			allow: [
				path.resolve(__dirname)
			]
		}
	},
	build: {
		outDir: './dist',
		// See https://tauri.app/v1/references/webview-versions for details
		target: process.env.TAURI_PLATFORM == 'windows' ? 'chrome105' : 'safari15',
		minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
		sourcemap: !!process.env.TAURI_DEBUG,
		emptyOutDir: true,
	},
})
