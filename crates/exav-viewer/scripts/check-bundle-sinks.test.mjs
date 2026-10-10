// The bundle scan must refuse a sink a dependency update could bring, and
// allow the reviewed occurrences, as they read in the built code.
import { describe, expect, it } from "vitest";

import { ALLOWED, checkBundles, scan } from "./check-bundle-sinks.mjs";

/** The reviewed occurrences, as they read in the bundles built from the current dependencies. */
const KNOWN = [
  'function m5(e,t){if(!e||(e.innerHTML="",!t||!Number.isFinite(t.x)',
  'let u=Math.max(4,Math.round(s*.42));c.innerHTML=`<svg width="${u}" height="${u}" viewBox="0 0 10 6" aria-hidden="true">',
  "height:${24*o.zoom}px;`,t.innerHTML='<svg viewBox=\"0 0 24 24\" width=\"100%\" height=\"100%\" aria-hidden",
  'case"script":u=i.createElement("div"),u.innerHTML="<script><\\/script>",u=u.removeChild(u.firstChild);',
  "if(n.children!=null)throw Error(s(60));u?.__html!==e&&(t.innerHTML=e)}}break;",
  'case"suppressHydrationWarning":case"innerHTML":case"ref":break;',
  'return;case"dangerouslySetInnerHTML":if(a!=null){',
  "return _0.test(\"\"+t)?\"javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')\":t}",
  'return typeof i=="string"&&i.length>0?`Function(${i})`:"Function"}',
  "  importScripts(p ? p.createScriptURL(${t}) : ${t});",
  "this._lowerCaseName=s}parseFromString(t){if(this._currentFragment=[],this._stack=[]",
  "let s=new pi({lowerCaseName:!0}).parseFromString(t);",
  'try{s.parseFromString(t["xdp:xdp"])}catch{}',
  'case"document":return c.text().then(h=>new DOMParser().parseFromString(h,o));case"json":',
];

const PLANTED = [
  "el.innerHTML=t.title",
  'el.innerHTML="<b>"+name+"</b>"',
  "e.outerHTML=s",
  'e.insertAdjacentHTML("beforeend",h)',
  "document.write(x)",
  "r.createContextualFragment(h)",
  "f.srcdoc=h",
  "eval(code)",
  'new Function("return "+s)',
  'a.href="javascript:"+code',
  "importScripts(u)",
  'new DOMParser().parseFromString(xml,"text/html")',
  "e.setHTMLUnsafe(h)",
];

describe("the bundle scan", () => {
  it("allows each reviewed occurrence, and every entry is one of them", () => {
    const files = KNOWN.map((text, i) => ({ path: `known-${i}.js`, text }));
    expect(checkBundles(files)).toEqual({ refused: [], stale: [] });
    expect(scan(files).length).toBeGreaterThanOrEqual(ALLOWED.length);
  });

  for (const code of PLANTED) {
    it(`refuses \`${code}\``, () => {
      const text = `var a=1;function f(t){${code}}var b=2;`;
      const { refused } = checkBundles([{ path: "x.js", text }], ALLOWED);
      expect(refused).toHaveLength(1);
    });
  }

  it("refuses a sink beside an allowed one", () => {
    const { refused } = checkBundles([{ path: "x.js", text: `${KNOWN[0]};function g(e,h){e.innerHTML=h}` }], ALLOWED);
    expect(refused.map((r) => r.sink)).toEqual(["innerHTML"]);
  });

  it("reports an entry nothing matches", () => {
    const { stale } = checkBundles([{ path: "x.js", text: KNOWN[0] }], ALLOWED);
    expect(stale).toHaveLength(ALLOWED.length - 1);
  });
});
