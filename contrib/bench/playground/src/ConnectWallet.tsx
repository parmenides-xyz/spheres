import * as React from 'react'
import { useConnect, useConnection, useConnectors, useDisconnect } from 'wagmi'
import { filterSupportedInjectedConnectors } from './explorer/wallets'
import { Button } from './explorer/SimulateShared'
import { cx } from './explorer/css'

export function ConnectWallet({ disabled }: { disabled: boolean }) {
	const connect = useConnect()
	const connectors = useConnectors()
	const { address, connector } = useConnection()
	const disconnect = useDisconnect()
	const [pendingId, setPendingId] = React.useState<string | null>(null)
	const injectedConnectors = React.useMemo(
		() => filterSupportedInjectedConnectors(connectors),
		[connectors],
	)
	if (address)
		return <Button disabled={disabled} onClick={() => disconnect.mutate({ connector })}>Disconnect</Button>

	const brandedConnectors = injectedConnectors.filter(
		(candidate) => candidate.id !== 'injected' && candidate.name !== 'Injected',
	)
	const prioritizedConnectors = brandedConnectors.length > 0 ? brandedConnectors :
		injectedConnectors.filter((candidate) => candidate.id === 'injected' && 'ethereum' in window)

	if (!prioritizedConnectors.length)
		return <span className="label-12 text-secondary">No wallet found.</span>

	return <div className="flex flex-wrap items-center gap-1.5">
		{prioritizedConnectors.map((connector) => (
			<Button type="button" key={connector.uid} disabled={disabled || connect.isPending}
				onClick={() => {
					setPendingId(connector.id)
					connect.mutate({ connector }, { onSettled: () => setPendingId(null) })
				}}
				className={cx('flex gap-[8px] items-center', pendingId === connector.id && connect.isPending && 'animate-pulse')}
			>
				{connector.icon && <img className="size-[12px] rounded-[2px]" src={connector.icon} alt="" />}
				{connector.name && connector.name !== 'Injected' ? `Connect ${connector.name}` : 'Connect Wallet'}
			</Button>
		))}
		{connect.isError && <span role="alert" className="text-negative">{connect.error.message}</span>}
	</div>
}
