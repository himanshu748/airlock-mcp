export function Section({
  id,
  eyebrow,
  title,
  lede,
  children,
}: {
  id?: string;
  eyebrow: string;
  title: string;
  lede?: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="rule-top scroll-mt-16 px-6 py-20 lg:px-8 lg:py-28">
      <div className="shell">
        <p className="label mb-4">{eyebrow}</p>
        <h2 className="max-w-[22ch] font-display text-[clamp(26px,3.4vw,40px)] leading-[1.1] font-bold tracking-[-0.015em]">
          {title}
        </h2>
        {lede && (
          <p className="mt-5 max-w-[62ch] text-[16px] leading-relaxed text-pencil">
            {lede}
          </p>
        )}
        <div className="mt-12" data-reveal>
          {children}
        </div>
      </div>
    </section>
  );
}
