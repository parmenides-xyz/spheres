import { Choices } from 'regen-ui'
import type * as React from 'react'
import { cx } from './css'

/**
 * One control, N mutually exclusive states — the pane split, Decoded/Raw in a
 * panel toolbar, Decoded/Hex in the calldata field. One implementation so
 * "same value, different representation" always looks the same.
 */
export function SegmentedControl<T extends string>(
	props: SegmentedControl.Props<T>,
): React.JSX.Element {
	const { value, options, onChange, size = 'md' } = props
	return (
		<Choices
			label={options.map((option) => option.label).join(' / ')}
			value={value}
			onChange={onChange}
			variant="compact"
			className={cx(
				'rounded-body bg-pane',
				size === 'sm' && '[&_[role=radio]]:h-5',
			)}
			items={options.map((option) => ({
				value: option.value,
				label: <span title={option.title}>{option.label}</span>,
			}))}
		/>
	)
}

export declare namespace SegmentedControl {
	interface Props<T extends string> {
		value: T
		options: ReadonlyArray<{ value: T; label: string; title?: string }>
		onChange: (value: T) => void
		size?: 'sm' | 'md'
	}
}
