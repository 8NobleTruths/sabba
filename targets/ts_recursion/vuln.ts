// The TypeScript twin of node_recursion: recursion once per character with no depth limit,
// so a long input throws "Maximum call stack size exceeded" (CWE-674). Sabba transpiles this
// to JavaScript with tsc before fuzzing, which is how the Node prover reaches TypeScript
// targets.
function deep(s: string, i: number): number {
  return i >= s.length ? i : deep(s, i + 1);
}

export function run(data: Buffer): number {
  return deep(Buffer.from(data).toString("latin1"), 0);
}
