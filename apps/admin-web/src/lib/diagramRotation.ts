export function signedRotationDelta(previousAngle: number, nextAngle: number) {
  let delta = nextAngle - previousAngle;
  while (delta > 180) delta -= 360;
  while (delta < -180) delta += 360;
  return delta;
}
