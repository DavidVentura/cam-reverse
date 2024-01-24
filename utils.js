const matchy = /%[0-9.-]*([a-z])/g;
const replacy = /(?<pre>.*?)%(?<num>[0-9.-]+)*(?<formatter>[a-z])/gs;

export const placeholderTypes = (str) => {
  // '%-16s, line %4d, %-16s:ret=%d,broadcast lan_seach to %s:%.3f!!!!'
  // =>
  // [ 's', 'd', 's', 'd', 's', 'f' ]
  return [...str.matchAll(matchy)].map((m) => m[1]);
};
export const sprintf = (str, values) => {
  // '%-16s, line %4d, %-16s:ret=%d,broadcast lan_seach to %s:%.3f!!!!' +
  // ["asd", 20, ...]
  // =>
  // asd, line 20, ...
  const matches = str.matchAll(replacy);
  return [...matches]
    .map((m, idx) => {
      const cur = values[idx];
      const val = m.groups.formatter == "x" ? `0x${cur.toString(16)}` : cur.toString();
      return m.groups.pre + val;
    })
    .join("");
};
