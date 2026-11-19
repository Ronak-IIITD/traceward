import { test, expect } from "@playwright/test";

test("real scanner finds input flow, selects sink and exports same JSON", async ({page}) => {
  let requests = 0;
  page.on("request", request => { if (request.url().endsWith("/api/v1/scans/snippet")) requests++; });
  await page.goto("/");
  await expect(page.getByRole("heading", {name: "Follow the evidence."})).toBeVisible();
  expect(requests).toBe(0);
  await page.getByRole("button", {name: "Scan Java", exact: true}).click();
  await expect(page.getByRole("heading", {name: "Potential SQL injection via query concatenation"})).toBeVisible();
  expect(requests).toBe(1);
  await expect(page.getByText("medium confidence", {exact: true})).toBeVisible();
  await page.getByRole("button", {name: "sink Statement.executeQuery Line 8"}).click();
  const selected = await page.getByRole("textbox", {name: "Java source code"}).evaluate((element: HTMLTextAreaElement) =>
    element.value.slice(element.selectionStart, element.selectionEnd));
  expect(selected).toBe("statement.executeQuery(query)");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", {name: "Export JSON"}).click();
  expect((await downloadPromise).suggestedFilename()).toBe("traceward-results.json");
  await page.screenshot({path: "test-results/workspace.png", fullPage: true});
  await page.getByRole("textbox", {name: "Java source code"}).fill("class Changed {}");
  await expect(page.getByText("Source changed.", {exact: false})).toBeVisible();
});

test("safe parameterization and invalid syntax get distinct results", async ({page}) => {
  await page.goto("/");
  await page.getByRole("button", {name: "Parameterized", exact: true}).click();
  await page.getByRole("button", {name: "Scan Java", exact: true}).click();
  await expect(page.getByRole("heading", {name: "No supported findings", exact: true})).toBeVisible();
  await page.getByRole("textbox", {name: "Java source code"}).fill("class Broken { void (");
  await page.getByRole("button", {name: "Scan Java", exact: true}).click();
  await expect(page.getByRole("heading", {name: "Analysis needs attention"})).toBeVisible();
  await expect(page.getByText("PARSE_ERROR", {exact: true}).first()).toBeVisible();
});

test("explicit failures and input limits stay actionable", async ({page}) => {
  await page.goto("/");
  await page.route("**/api/v1/scans/snippet", route => route.fulfill({
    status: 503, json: {error: {message: "The scanner is unavailable."}}
  }));
  await page.getByRole("button", {name: "Scan Java", exact: true}).click();
  await expect(page.getByRole("alert").filter({hasText: "The scanner is unavailable."})).toHaveText("The scanner is unavailable.");
  await page.getByRole("button", {name: "Clear", exact: true}).click();
  await expect(page.getByRole("button", {name: "Scan Java", exact: true})).toBeDisabled();
  await page.getByRole("textbox", {name: "Java source code"}).fill("a".repeat(65537));
  await expect(page.getByRole("button", {name: "Scan Java", exact: true})).toBeDisabled();
});

test("methodology and mobile workspace remain usable", async ({page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await page.goto("/");
  await expect(page.getByRole("button", {name: "Scan Java", exact: true})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("link", {name: "Coverage & methods"}).click();
  await expect(page.getByRole("heading", {name: "Know what was analyzed."})).toBeVisible();
  await expect(page.getByRole("cell", {name: "CWE-89", exact: true})).toBeVisible();
  await page.getByRole("link", {name: "Return to scan workspace"}).click();
  await expect(page.getByRole("textbox", {name: "Java source code"})).toBeVisible();
});

test("proxy rejects oversized requests", async ({request}) => {
  const response = await request.post("/api/v1/scans/snippet", {
    headers: {"content-type": "application/json"}, data: " ".repeat(256 * 1024 + 1)
  });
  expect(response.status()).toBe(413);
  expect((await response.json()).error.code).toBe("INPUT_TOO_LARGE");
});
