import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Amount, Copy } from 'regen-ui'
import { formatUnits, toHex } from 'viem'
import { useConnection } from 'wagmi'
import { ConnectWallet } from './ConnectWallet'
import { InfoCard } from './explorer/InfoCard'
import { Midcut } from './explorer/Midcut'
import { SegmentedControl } from './explorer/PanelToolbar'
import { Button, Field, inputClass } from './explorer/SimulateShared'
import './style.css'

type Account = { address: string; arcBalance: string; sphereBalance: string }
type Accounts = { accounts: Account[]; csrfToken: string }
type Action = 'payment' | 'deposit' | 'withdraw'
type Receipt = {
	hash: string
	chain: 'arc' | 'sphere'
	blockNumber: string | number | null
	status: 'confirmed' | 'pending' | 'reverted'
	creditHash?: string
	creditBlockNumber?: string | number
	settlementHash?: string
	payoutHash?: string
	payoutBlockNumber?: string | number
}

const actions = {
	payment: { label: 'Payment', submit: 'Send payment', route: 'Sphere → Sphere' },
	deposit: { label: 'Encrypted deposit', submit: 'Deposit USDC', route: 'Arc → Sphere' },
	withdraw: { label: 'Withdrawal', submit: 'Withdraw USDC', route: 'Sphere → Arc' },
} as const

async function request<T>(path: string, init?: RequestInit): Promise<T> {
	const response = await fetch(path, init)
	const data = await response.json()
	if (!response.ok) throw new Error(data.error || response.statusText)
	return data
}

function Balance({ value }: { value: string }) {
	const units = BigInt(value)
	return <Amount amount={{ amount: toHex(units), formatted: formatUnits(units, 6), decimals: 6, symbol: 'USDC' }}
		precise maxDecimals={6} />
}

function ReceiptDetails({ receipt }: { receipt: Receipt }) {
	const hash = (value: string) => <>
		<Midcut value={value} prefix="0x" align="end" />
		<Copy value={value} />
	</>
	return <InfoCard title={<InfoCard.Title>Transaction receipt</InfoCard.Title>} className="w-full!"
		sections={[
			{ label: 'Status', value: receipt.status },
			{ label: 'Network', value: receipt.chain === 'arc' ? 'Arc' : 'Sphere' },
			{ label: 'Transaction hash', value: hash(receipt.hash) },
			...(receipt.blockNumber == null ? [] : [{ label: 'Block', value: receipt.blockNumber }]),
			...(receipt.creditHash ? [{ label: 'Sphere credit', value: hash(receipt.creditHash) }] : []),
			...(receipt.creditBlockNumber == null ? [] : [{ label: 'Credit block', value: receipt.creditBlockNumber }]),
			...(receipt.settlementHash ? [{ label: 'Arc settlement', value: hash(receipt.settlementHash) }] : []),
			...(receipt.payoutHash ? [{ label: 'Arc payout', value: hash(receipt.payoutHash) }] : []),
			...(receipt.payoutBlockNumber == null ? [] : [{ label: 'Payout block', value: receipt.payoutBlockNumber }]),
		]} />
}

export function App() {
	const client = useQueryClient()
	const wallets = useQuery({
		queryKey: ['accounts'],
		queryFn: () => request<Accounts>('/api/accounts'),
		refetchInterval: 10_000,
	})
	const { address: connectedAddress } = useConnection()
	const [selection, setSelection] = useState<{ address?: string; sender: string }>()
	const sender = selection?.address === connectedAddress ? selection?.sender : undefined
	const connectedSelected = !!connectedAddress && (!sender || sender === 'connected')
	const [action, setAction] = useState<Action>('payment')
	const accounts = wallets.data?.accounts ?? []
	const account = accounts.find((user) => user.address === sender) ?? accounts[0]
	const recipient = action === 'payment' ? accounts.find((user) => user.address !== account?.address) : account
	const transaction = useMutation({
		mutationFn: (fields: { from: string; to: string; amount: string }) =>
			request<Receipt>('/api/' + action, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': wallets.data!.csrfToken },
				body: JSON.stringify(fields),
			}),
		onSuccess: () => client.invalidateQueries({ queryKey: ['accounts'] }),
	})
	const submitted = transaction.data
	const receipt = useQuery({
		queryKey: ['receipt', account?.address, submitted?.hash],
		enabled: submitted?.status === 'pending',
		queryFn: () => request<Receipt>('/api/receipt?' + new URLSearchParams({
			from: account!.address, hash: submitted!.hash, chain: submitted!.chain,
		})),
		refetchInterval: (query) => query.state.data?.status === 'pending' ? 2_000 : false,
	})
	const latest = receipt.data ?? submitted
	const busy = transaction.isPending || latest?.status === 'pending'
	return <main className="flex flex-col gap-6 px-4 pt-8 sm:pt-20 pb-16 max-w-3xl mx-auto w-full">
		<h1 className="heading-32">Spheres on Arc</h1>
		{wallets.isPending && <p role="status">Loading accounts…</p>}
		{wallets.isError && <p role="alert">{wallets.error.message} <Button onClick={() => wallets.refetch()}>Retry</Button></p>}
		{wallets.isSuccess && !account && !connectedAddress && <p>No demo accounts available.</p>}
			<InfoCard title={<InfoCard.Title>Account</InfoCard.Title>} className="w-full!"
				sections={[
					<div className="w-full"><Field label={<label htmlFor="sender">Account</label>}>
						<select id="sender" className={inputClass()} value={connectedSelected ? 'connected' : account?.address} disabled={busy}
							onChange={(event) => { setSelection({ address: connectedAddress, sender: event.target.value }); transaction.reset() }}>
							{connectedAddress && <option value="connected">Connected wallet · {connectedAddress}</option>}
							{accounts.map((user, i) => <option key={user.address} value={user.address}>Account {i + 1} · {user.address}</option>)}
						</select>
					</Field></div>,
					{ label: 'Wallet', value: <ConnectWallet disabled={busy} /> },
					...(connectedSelected && connectedAddress ? [
						{ label: 'Address', value: <><Midcut value={connectedAddress} prefix="0x" align="end" /><Copy value={connectedAddress} /></> },
						<p>Private balances and transactions require Sphere wallet authorization.</p>,
					] : account ? [
						{ label: 'Balance (Arc)', value: <Balance value={account.arcBalance} /> },
						{ label: 'Balance (Sphere)', value: <Balance value={account.sphereBalance} /> },
					] : []),
				]} />
			{account && !connectedSelected && <><InfoCard title={<InfoCard.Title>Transaction</InfoCard.Title>} className="w-full!"
				sections={[
					<fieldset disabled={busy} className="flex flex-wrap items-center justify-between w-full gap-2">
						<SegmentedControl value={action} options={(Object.keys(actions) as Action[]).map((value) => ({ value, label: actions[value].label }))}
							onChange={(value) => { if (!busy) { setAction(value); transaction.reset() } }} />
						<span className="label-12 text-tertiary">{actions[action].route}</span>
					</fieldset>,
					<form key={account.address + action} className="flex w-full flex-col gap-4"
						onSubmit={(event) => {
							event.preventDefault()
							if (busy) return
							const formData = new FormData(event.target as HTMLFormElement)
							const recipient = String(formData.get('recipient')).trim()
							const amount = String(formData.get('amount')).trim()
							transaction.mutate({ from: account.address, to: recipient, amount })
						}}
					>
						<Field label={<label htmlFor="recipient">Recipient address</label>}>
							<input className={inputClass()} id="recipient" type="text" name="recipient" placeholder="0x..."
								list="demo-accounts" required pattern="0x[0-9a-fA-F]{40}" defaultValue={recipient?.address ?? ''} />
							<datalist id="demo-accounts">{accounts.map((user, i) => <option key={user.address} value={user.address}>Account {i + 1}</option>)}</datalist>
						</Field>
						<Field label={<label htmlFor="amount">Amount (USDC)</label>}>
							<input className={inputClass()} id="amount" required name="amount" type="number" min="0.000001" step="0.000001" inputMode="decimal" placeholder="0.00" />
						</Field>
						<div><Button tone="primary" type="submit" disabled={busy}>
							{busy ? 'Awaiting confirmation…' : actions[action].submit}
						</Button></div>
						{transaction.isError && <p role="alert" className="text-negative">{transaction.error.message}</p>}
					</form>,
				]} />
			<div aria-live="polite">{latest && <ReceiptDetails receipt={latest} />}{receipt.error && <p role="alert">{receipt.error.message} <Button onClick={() => receipt.refetch()}>Refresh receipt</Button></p>}</div></>}
	</main>
}
