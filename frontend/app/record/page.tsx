import type { Metadata } from "next";
import { RecordView } from "./RecordView";

export const metadata: Metadata = {
  title: "Airlock inspection record",
  description:
    "What the server declared, and what Airlock observed, side by side.",
};

export default function RecordPage() {
  return <RecordView />;
}
