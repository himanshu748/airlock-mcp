export const DISCLAIMER =
  "Airlock reports what it observed. Absence of a finding is not proof of safety.";

export function DisclaimerBar({ text }: { text?: string }) {
  return (
    <footer className="border-t border-pencil-dim px-6 py-8 lg:px-10">
      <p className="font-mono text-[13px] leading-relaxed text-pencil">
        {text || DISCLAIMER}
      </p>
    </footer>
  );
}
