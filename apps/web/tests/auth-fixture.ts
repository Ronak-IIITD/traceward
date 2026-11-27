import { expect, type Page } from "@playwright/test";

export const testWorkspaceKey = "test-only-workspace-key-used-by-loopback-playwright";

export async function signInToWorkspace(page: Page) {
  await page.goto("/workspace");
  await page.getByLabel("Workspace key", { exact: true }).fill(testWorkspaceKey);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/workspace$/);
}
