import { TextArea } from "@heroui/react";
import { forwardRef, useCallback, useImperativeHandle, useLayoutEffect, useRef, type ComponentProps } from "react";

type Props = Omit<ComponentProps<typeof TextArea>, "ref" | "rows"> & { minRows?: number; maxRows?: number };

/** Native HeroUI textarea with bounded content sizing; never modifies the field's value or focus. */
export const AutoSizeTextArea = forwardRef<HTMLTextAreaElement, Props>(function AutoSizeTextArea(
  { minRows = 3, maxRows = 8, value, defaultValue, onInput, className, ...props }, forwardedRef,
) {
  const elementRef = useRef<HTMLTextAreaElement>(null);
  useImperativeHandle(forwardedRef, () => elementRef.current!);
  const resize = useCallback(() => {
    const element = elementRef.current;
    if (!element) return;
    const style = getComputedStyle(element);
    const number = (text: string) => Number.parseFloat(text) || 0;
    const line = number(style.lineHeight) || number(style.fontSize) * 1.5;
    const padding = number(style.paddingTop) + number(style.paddingBottom);
    const border = number(style.borderTopWidth) + number(style.borderBottomWidth);
    const minimum = Math.max(1, minRows) * line + padding;
    const maximum = Math.max(Math.max(1, minRows), maxRows) * line + padding;
    element.style.height = "auto";
    const height = Math.min(maximum, Math.max(minimum, element.scrollHeight));
    element.style.height = `${height + (style.boxSizing === "border-box" ? border : -padding)}px`;
    element.style.overflowY = element.scrollHeight > maximum ? "auto" : "hidden";
  }, [minRows, maxRows]);
  useLayoutEffect(resize, [resize, value, defaultValue]);
  useLayoutEffect(() => {
    const element = elementRef.current;
    if (!element) return;
    let width = element.getBoundingClientRect().width;
    const observer = new ResizeObserver(() => {
      const next = element.getBoundingClientRect().width;
      if (next !== width) { width = next; resize(); }
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, [resize]);
  return <TextArea {...props} ref={elementRef} value={value} defaultValue={defaultValue} rows={minRows}
    className={["resize-none", className].filter(Boolean).join(" ")}
    onInput={(event) => { onInput?.(event); resize(); }} />;
});
