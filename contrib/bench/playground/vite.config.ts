import tailwind from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
	plugins: [react(), tailwind()],
	server: {
		host: '127.0.0.1',
		port: 15151,
		strictPort: true,
		proxy: { '/api': 'http://127.0.0.1:15152' },
	},
})
