export type DiagramGestureEvent = Pick<Event, "type"> & {
  pointerType?: string;
};

export function isTouchGesture(event: DiagramGestureEvent) {
  return event.type.startsWith("touch") || event.pointerType === "touch";
}

export function preserveTouchTap<T extends DiagramGestureEvent>(
  dragStart: (event: T) => void,
) {
  return (event: T) => {
    if (!isTouchGesture(event)) dragStart(event);
  };
}
