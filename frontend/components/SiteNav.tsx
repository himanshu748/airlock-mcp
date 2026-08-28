import Link from "next/link";

const LINKS = [
  ["The gap", "#gap"],
  ["How it works", "#how"],
  ["See it run", "#run"],
  ["Checks", "#checks"],
  ["Output", "#output"],
];

export function SiteNav() {
  return (
    <header className="sticky top-0 z-50 border-b border-pencil-dim/50 bg-slate/85 backdrop-blur">
      <div className="shell flex items-center justify-between gap-6 px-6 py-3.5 lg:px-8">
        <Link href="/" className="flex items-baseline gap-3 no-underline">
          <span className="font-display text-[15px] font-bold tracking-[0.22em] uppercase text-form">
            Airlock
          </span>
          <span aria-hidden="true" className="hidden h-px w-6 bg-pencil sm:block" />
        </Link>

        <nav className="hidden items-center gap-7 md:flex">
          {LINKS.map(([label, href]) => (
            <a
              key={href}
              href={href}
              className="font-mono text-[13px] text-pencil no-underline transition-colors hover:text-form"
            >
              {label}
            </a>
          ))}
        </nav>

        <Link href="/record/" className="btn btn-primary">
          Open the record
        </Link>
      </div>
    </header>
  );
}
