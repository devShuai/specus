import { ProgressBar } from "@heroui/react";
import type { ComponentProps } from "react";

/** A complete native meter: the root alone exposes ARIA values but paints no progress. */
export function ProgressMeter(props: Omit<ComponentProps<typeof ProgressBar>, "children">) {
  return <ProgressBar {...props}><ProgressBar.Track><ProgressBar.Fill /></ProgressBar.Track></ProgressBar>;
}
