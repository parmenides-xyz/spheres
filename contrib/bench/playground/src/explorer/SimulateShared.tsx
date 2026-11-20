import { Button as RegenButton } from 'regen-ui'
import type * as React from 'react'
import { cx } from './css'

/** Label above a control. */
export function Field(props: Field.Props): React.JSX.Element {
	return (
		<div className="flex min-w-0 flex-col gap-[5px]">
			<div className="flex items-center justify-between gap-[8px]">
				<span className="font-sans label-12 text-tertiary">{props.label}</span>
				{props.action}
			</div>
			{props.children}
			{props.hint && (
				<span
					className={cx(
						'type-card',
						props.invalid ? 'text-negative' : 'text-content-dimmed',
					)}
				>
					{props.hint}
				</span>
			)}
		</div>
	)
}

export declare namespace Field {
	interface Props {
		label: React.ReactNode
		children: React.ReactNode
		/** Right-aligned control on the label line — a mode toggle, a link. */
		action?: React.ReactNode
		hint?: React.ReactNode
		invalid?: boolean
	}
}

const inputClassName =
	'w-full min-w-0 rounded-body border border-card-border bg-pane px-[12px] py-[9px] type-card-data text-primary outline-none transition-colors placeholder:text-field-content-secondary focus:border-focus'

/** Invalid state is applied on blur, never on mount — see `draftFieldErrors`. */
export function inputClass(invalid?: boolean): string {
	return cx(inputClassName, invalid && 'border-negative focus:border-negative')
}

/** A primary action. There is at most one per pane. */
export function Button(props: Button.Props): React.JSX.Element {
	const { tone = 'default', ...rest } = props
	return (
		<RegenButton
			type="button"
			{...rest}
			size="small"
			variant={tone === 'primary' ? 'primary' : 'secondary'}
		/>
	)
}

export declare namespace Button {
	interface Props extends React.ButtonHTMLAttributes<HTMLButtonElement> {
		tone?: 'default' | 'primary'
	}
}
