import { expect, it } from "vitest";

import { isSvg, svgSize } from "./svg.js";

const size = (text: string) => svgSize(new TextEncoder().encode(text));

it("reads the size an SVG states, its viewBox otherwise", () => {
  expect(size('<svg xmlns="http://www.w3.org/2000/svg" width="40" height="30px">')).toEqual({ width: 40, height: 30 });
  expect(size('<?xml version="1.0"?>\n<svg viewBox="0 0 200 100">')).toEqual({ width: 200, height: 100 });
  expect(size("<svg viewBox='0,0,200,100' width='50'>")).toEqual({ width: 50, height: 25 });
  expect(size('<svg viewBox="0 0 200 100" height="50">')).toEqual({ width: 100, height: 50 });
  // A size in another unit or in percent says nothing in pixels.
  expect(size('<svg width="100%" height="10cm" viewBox="0 0 4 3">')).toEqual({ width: 4, height: 3 });
  expect(size('<svg width="10cm">')).toEqual({ width: 300, height: 150 });
  expect(size("not an svg")).toEqual({ width: 300, height: 150 });
  expect(size('<svg viewBox="0 0 -1 5">')).toEqual({ width: 300, height: 150 });
});

it("knows an SVG by its type or its name", () => {
  expect(isSvg({ type: "image/svg+xml", name: "x" })).toBe(true);
  expect(isSvg({ name: "Logo.SVG" })).toBe(true);
  expect(isSvg({ name: "logo.svgz" })).toBe(false);
});
