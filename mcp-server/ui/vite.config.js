import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/',

  // Force a single React instance
  resolve: {
    dedupe: ['react', 'react-dom', 'react/jsx-runtime'],
  },

  // Helps Vite prebundle consistently
  optimizeDeps: {
    include: ['react', 'react-dom', 'react/jsx-runtime'],
  },

  build: {
    outDir: 'dist',
    sourcemap: true, // (optional but recommended for debugging)
  },
})
