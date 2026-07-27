import assert from "node:assert/strict";
import test from "node:test";

import { isSupportedUploadFile, mergeUploadFiles, removeUploadFile } from "./uploadFiles.js";

const file = (name, size = 100) => ({ name, size });

test("separate monthly drops accumulate instead of overwriting", () => {
  const firstDrop = mergeUploadFiles([], [file("may-2026.csv")]);
  const secondDrop = mergeUploadFiles(firstDrop, [file("june-2026.csv")]);

  assert.deepEqual(secondDrop.map((item) => item.name), ["may-2026.csv", "june-2026.csv"]);
});

test("a same-name file replaces its earlier version without duplicating it", () => {
  const initial = [file("may-2026.csv", 100), file("june-2026.csv", 200)];
  const merged = mergeUploadFiles(initial, [file("MAY-2026.CSV", 999)]);

  assert.equal(merged.length, 2);
  assert.equal(merged[0].size, 999);
  assert.equal(merged[1].name, "june-2026.csv");
});

test("a selected monthly file can be removed independently", () => {
  const files = [file("may-2026.csv"), file("june-2026.csv"), file("july-2026.csv")];
  const remaining = removeUploadFile(files, files[1]);

  assert.deepEqual(remaining.map((item) => item.name), ["may-2026.csv", "july-2026.csv"]);
});

test("modern CSV and Excel uploads are accepted while legacy XLS is rejected", () => {
  assert.equal(isSupportedUploadFile(file("report.csv")), true);
  assert.equal(isSupportedUploadFile(file("report.XLSX")), true);
  assert.equal(isSupportedUploadFile(file("report.xls")), false);
  assert.equal(isSupportedUploadFile(file("report.pdf")), false);
});
