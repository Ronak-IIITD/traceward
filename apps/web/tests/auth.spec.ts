import { expect, test } from "@playwright/test";
import { testWorkspaceKey } from "./auth-fixture";

const endpoint = "/api/v1/scans/snippet";
const snippet = { language: "java", code: "class Safe {}" };

test("landing, signed workspace session and sign-out work end to end", async ({
  page,
  context,
  request,
}, testInfo) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "TraceWard", exact: true })).toBeVisible();
  await expect(page.getByText("Source is processed in memory and never executed.")).toBeVisible();
  const artwork = page.locator('img[src="/images/lighthouse.webp"]');
  await expect(artwork).toHaveJSProperty("complete", true);
  expect(await artwork.evaluate((image: HTMLImageElement) => image.naturalWidth)).toBeGreaterThan(
    0,
  );
  await page.screenshot({ path: testInfo.outputPath("landing-desktop.png") });
  expect((await page.request.post(endpoint, { data: snippet })).status()).toBe(401);

  await page.getByRole("link", { name: "Open workspace" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.screenshot({ path: testInfo.outputPath("sign-in-desktop.png") });
  const field = page.getByLabel("Workspace key", { exact: true });
  const submit = page.getByRole("button", { name: "Sign in", exact: true });
  await field.fill("incorrect workspace key");
  await submit.click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText("didn’t match");
  expect(await context.cookies()).toHaveLength(0);

  await field.fill(testWorkspaceKey);
  await submit.click();
  await expect(page).toHaveURL(/\/workspace$/);
  const session = (await context.cookies()).find(({ name }) => name === "traceward_workspace");
  if (!session) throw new Error("Sign-in did not set a workspace session.");
  expect(session).toMatchObject({ httpOnly: true, sameSite: "Strict" });
  expect(session.value).not.toContain(testWorkspaceKey);
  const last = session.value.endsWith("a") ? "b" : "a";
  const tampered = await request.post(endpoint, {
    headers: { cookie: session.name + "=" + session.value.slice(0, -1) + last },
    data: snippet,
  });
  expect(tampered.status()).toBe(401);
  expect((await page.request.post(endpoint, { data: snippet })).status()).toBe(200);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect((await page.request.post(endpoint, { data: snippet })).status()).toBe(401);
  await page.goto("/workspace");
  await expect(page).toHaveURL(/\/login$/);
});

test("landing and sign-in remain usable on mobile", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Open workspace" })).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await page.screenshot({ path: testInfo.outputPath("landing-mobile.png"), fullPage: true });
  await page.getByRole("link", { name: "Sign in", exact: true }).click();
  await expect(page.getByLabel("Workspace key", { exact: true })).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
});
