import { buttonVariants, type ButtonProps } from "@heroui/react";
import { Link, type LinkProps } from "react-aria-components/Link";

type ButtonLinkProps = LinkProps & Pick<ButtonProps, "size" | "variant" | "isIconOnly">;

/** A real, keyboard-accessible link with the app's button styling, not a button pretending to navigate. */
export function ButtonLink({ size, variant, isIconOnly, className, ...props }: ButtonLinkProps) {
  return <Link {...props} className={(state) => [
    buttonVariants({ size, variant, isIconOnly }),
    typeof className === "function" ? className(state) : className,
  ].filter(Boolean).join(" ")} />;
}
