import Link from "next/link";

export function Wordmark({ tagline }: { tagline?: string }) {
  return (
    <Link href="/" className="group flex items-baseline gap-3.5 no-underline">
      <span className="font-display text-[15px] font-bold uppercase tracking-[0.22em] text-form">
        Airlock
      </span>
      <span
        aria-hidden="true"
        className="h-px w-7 bg-pencil transition-colors group-hover:bg-form"
      />
      {tagline && (
        <span className="font-mono text-[13px] text-pencil">{tagline}</span>
      )}
    </Link>
  );
}
