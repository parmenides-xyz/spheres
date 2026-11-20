import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { WagmiProvider } from 'wagmi'
import { walletConfig } from './wallet'
import { App } from './App.tsx'

const queryClient = new QueryClient()

const root = document.querySelector('div#root')
if (!root) throw new Error('Root element not found')

createRoot(root).render(
	<StrictMode>
		<WagmiProvider config={walletConfig}>
			<QueryClientProvider client={queryClient}>
				<App />
			</QueryClientProvider>
		</WagmiProvider>
	</StrictMode>,
)
