import { Tooltip, TooltipContent, TooltipTrigger } from "@heroui/react";
import type { ReactElement } from "react";

/** Enabled controls own focus; only disabled controls need a focusable explanation. */
export function ActionTooltip({ children, disabled, label, placement, delay = 0 }: {
  children: ReactElement;
  disabled?: boolean;
  label: string;
  placement?: "top" | "bottom";
  delay?: number;
}) {
  return (
    <Tooltip delay={delay}>
      {disabled ? (
        <TooltipTrigger role="group" className="inline-flex" tabIndex={0} aria-label={label}>
          {children}
        </TooltipTrigger>
      ) : children}
      <TooltipContent placement={placement}>{label}</TooltipContent>
    </Tooltip>
  );
}
