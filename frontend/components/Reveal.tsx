"use client";

import { useEffect } from "react";

/**
 * Reveals `[data-reveal]` blocks as they enter the viewport.
 *
 * Content is never hidden in a way that can strand it. The hidden state is
 * applied here rather than in the stylesheet, so no JavaScript means no
 * hiding; anything already on screen at mount is never hidden; printing
 * reveals whatever is still pending; and the stylesheet drops the effect
 * entirely under prefers-reduced-motion.
 */
export function Reveal() {
  useEffect(() => {
    const targets = Array.from(
      document.querySelectorAll<HTMLElement>("[data-reveal]"),
    );
    if (targets.length === 0) return;

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const pending = new Set<HTMLElement>();
    for (const target of targets) {
      if (target.getBoundingClientRect().top < window.innerHeight * 0.95) {
        continue;
      }
      target.dataset.revealReady = "true";
      pending.add(target);
    }
    if (pending.size === 0) return;

    const reveal = (element: HTMLElement) => {
      element.dataset.revealed = "true";
      pending.delete(element);
    };

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          reveal(entry.target as HTMLElement);
          observer.unobserve(entry.target);
        }
      },
      { rootMargin: "0px 0px -10% 0px", threshold: 0.05 },
    );
    for (const target of pending) observer.observe(target);

    // Printing never scrolls, so anything still pending would print blank.
    const revealForPrint = () => {
      for (const target of Array.from(pending)) reveal(target);
    };
    window.addEventListener("beforeprint", revealForPrint);

    return () => {
      window.removeEventListener("beforeprint", revealForPrint);
      observer.disconnect();
    };
  }, []);

  return null;
}
