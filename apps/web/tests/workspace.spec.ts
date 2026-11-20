import { test, expect } from "@playwright/test";

test("real scanner finds input flow, selects sink and exports same JSON", async ({page}) => {
  let requests = 0;
  page.on("request", request => { if (request.url().endsWith("/api/v1/scans/snippet")) requests++; });
  await page.goto("/");
  await expect(page.getByRole("heading", {name: "Scan workspace", exact: true})).toBeVisible();
  expect(requests).toBe(0);
  await page.getByRole("button", {name: "Scan Java", exact: true}).click();
  await expect(page.getByRole("heading", {name: "Potential SQL injection via query concatenation"})).toBeVisible();
  expect(requests).toBe(1);
  await expect(page.getByText("medium confidence", {exact: true})).toBeVisible();
  await page.getByRole("button", {name: "sink Statement.executeQuery Line 8"}).click();
  const selected = await page.getByRole("textbox", {name: "Java source code"}).evaluate(() => window.getSelection()?.toString());
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
  await expect(page.getByRole("heading", {name: "No SQL injection paths found", exact: true})).toBeVisible();
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
  await page.screenshot({path:"test-results/workspace-mobile.png",fullPage:true});
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

test("example CTA moves from idle through loading to selectable real evidence", async ({page, context}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  let finish!: () => void;
  const hold = new Promise<void>(resolve => { finish = resolve; });
  await page.route("**/api/v1/scans/snippet", async route => {
    await hold;
    await route.continue();
  });
  await page.goto("/");
  await expect(page.getByRole("heading", {name: "Ready to trace"})).toBeVisible();
  await page.screenshot({path: "test-results/workspace-empty.png", fullPage: true});
  await page.getByRole("button", {name: "Try the vulnerable example"}).click();
  await expect(page.getByText("Tracing supported flows")).toBeVisible();
  await expect(page.getByRole("button", {name: "Scanning", exact: true})).toBeDisabled();
  finish();
  await expect(page.locator(".cm-sink-marker").first()).toBeVisible();
  await page.getByRole("button", {name: "Potential SQL injection via query concatenation"}).click();
  expect(await page.evaluate(() => window.getSelection()?.toString())).toBe("statement.executeQuery(query)");
  await page.getByText("Suggested fix", {exact:true}).click();
  await page.getByRole("button", {name:"Copy example"}).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain("ps.setString(1, id)");
  await page.getByRole("button", {name:"Copy JSON"}).click();
  const report = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()));
  expect(report.summary.findings).toBe(1);
});

test("editor supports wrap, indentation, keyboard exit and shortcut, and retry after failure", async ({page}) => {
  await page.goto("/");
  const editor = page.getByRole("textbox", {name:"Java source code"});
  const wrap = page.getByRole("button", {name:"Soft wrap"});
  await wrap.click();
  await expect(wrap).toHaveAttribute("aria-pressed","false");
  await editor.focus();
  await page.keyboard.press("Tab");
  await expect(editor.locator(".cm-line").first()).toHaveText(/^\s+import/);
  await page.keyboard.press("Escape");
  await page.keyboard.press("Tab");
  await expect(editor).not.toBeFocused();
  await page.getByRole("button", {name:"Parameterized"}).click();
  await page.route("**/api/v1/scans/snippet", route => route.fulfill({
    status:503, json:{error:{message:"Temporary test failure."}},
  }), {times:1});
  await editor.press("Control+Enter");
  await expect(page.getByRole("region",{name:"Scan evidence"}).getByRole("alert")).toHaveText("Temporary test failure.");
  await page.getByRole("button",{name:"Retry scan"}).click();
  await expect(page.getByRole("heading", {name:"No SQL injection paths found"})).toBeVisible();
  await page.screenshot({path:"test-results/workspace-clean.png", fullPage:true});
});

test("UTF-8 trace locations select the right source for multiple findings", async ({page}) => {
  await page.goto("/");
  const editor = page.getByRole("textbox",{name:"Java source code"});
  await editor.fill([
    "class Example { void find(HttpServletRequest request, Statement statement) throws Exception {",
    'String café="🍵"; statement.executeQuery("Q" + request.getHeader("one"));',
    'statement.executeQuery("Q" + request.getParameter("two"));',
    "} }",
  ].join("\n"));
  await editor.press("Control+Enter");
  const cards = page.getByRole("button",{name:"Potential SQL injection via query concatenation"});
  await expect(cards).toHaveCount(2);
  await cards.nth(1).click();
  await page.getByRole("button",{name:"source HttpServletRequest.getParameter Line 3"}).click();
  expect(await page.evaluate(() => window.getSelection()?.toString())).toBe('request.getParameter("two")');
  await cards.first().click();
  await page.getByRole("button",{name:"source HttpServletRequest.getHeader Line 2"}).click();
  expect(await page.evaluate(() => window.getSelection()?.toString())).toBe('request.getHeader("one")');
  await editor.fill("class Edited {}");
  await expect(page.locator(".cm-evidence-source")).toHaveCount(0);
  await expect(page.getByRole("button",{name:"source HttpServletRequest.getHeader Line 2"})).toBeDisabled();
});
