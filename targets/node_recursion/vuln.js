// A parser that recurses once per input character with no depth limit. A long input drives
// the recursion past V8's call-stack limit and throws "Maximum call stack size exceeded", an
// input-driven stack exhaustion denial of service (CWE-674). Self-contained so a fuzzer can
// prove it with no network or external state.
function deep(s, i) {
  return i >= s.length ? i : deep(s, i + 1);
}

module.exports.run = function (data) {
  return deep(Buffer.from(data).toString("latin1"), 0);
};
