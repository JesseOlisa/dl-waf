import { cn } from "@/lib/utils";

interface BrandLogoProps {
  className?: string;
  markClassName?: string;
  showWordmark?: boolean;
  tagline?: string;
  wordmarkClassName?: string;
  taglineClassName?: string;
}

/**
 * Sterling Trust Bank identity — a gold shield with an "ST" monogram plus the
 * wordmark. Shared by the customer portal, the SOC sidebar, and the login page
 * so both surfaces read as one brand.
 */
export function BrandLogo({
  className,
  markClassName,
  showWordmark = true,
  tagline,
  wordmarkClassName,
  taglineClassName,
}: BrandLogoProps) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <BrandMark className={markClassName} />
      {showWordmark && (
        <div className="flex flex-col leading-tight">
          <span className={cn("text-base font-bold tracking-tight", wordmarkClassName)}>
            Sterling Trust <span className="text-brand-gold">Bank</span>
          </span>
          {tagline && (
            <span className={cn("text-[11px] font-medium opacity-70", taglineClassName)}>
              {tagline}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export function BrandMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 40 40"
      className={cn("size-8 shrink-0", className)}
      role="img"
      aria-label="Sterling Trust Bank"
    >
      <path
        d="M20 2 L34 7 V19 C34 28 28 34 20 38 C12 34 6 28 6 19 V7 Z"
        fill="var(--brand-navy)"
        stroke="var(--brand-gold)"
        strokeWidth="1.5"
      />
      <text
        x="20"
        y="25"
        textAnchor="middle"
        fontSize="15"
        fontWeight="700"
        fontFamily="var(--font-geist-sans, sans-serif)"
        fill="var(--brand-gold)"
      >
        ST
      </text>
    </svg>
  );
}
