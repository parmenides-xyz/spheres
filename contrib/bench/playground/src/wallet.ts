import { createConfig, http } from 'wagmi'
import { injected } from 'wagmi/connectors'
import { defineChain } from 'viem'

const arc = defineChain({
	id: 1337,
	name: 'Arc localnet',
	nativeCurrency: { name: 'USDC', decimals: 18, symbol: 'USDC' },
	rpcUrls: { default: { http: ['http://127.0.0.1:18549'] } },
})

export const walletConfig = createConfig({
	multiInjectedProviderDiscovery: true,
	chains: [arc],
	connectors: [injected()],
	transports: { [arc.id]: http() },
})
