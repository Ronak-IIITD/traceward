import { expect, test } from "@playwright/test";
import { signInToWorkspace } from "./auth-fixture";

test.use({ hasTouch: true });

function contrast(first: string, second: string) {
  function luminance(color: string) {
    const channels = color
      .match(/[\d.]+/g)
      ?.slice(0, 3)
      .map(Number);
    if (!channels || channels.length !== 3) throw new Error(`Expected an RGB color: ${color}`);
    const [red, green, blue] = channels.map((value) => {
      value /= 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    });
    return red * 0.2126 + green * 0.7152 + blue * 0.0722;
  }
  const values = [luminance(first), luminance(second)].sort((a, b) => a - b);
  return (values[1] + 0.05) / (values[0] + 0.05);
}

for (const width of [320, 768, 1440]) {
  test(`pages reflow within a ${width}px viewport`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    async function checkRoute(route: string) {
      await page.goto(route);
      await expect(page.locator("main")).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
    }
    await checkRoute("/");
    await checkRoute("/login");
    await checkRoute("/methodology");
    await signInToWorkspace(page);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
  });
}

test("public technical text loads its font and the key field has a visible boundary", async ({
  page,
}) => {
  await page.goto("/login");
  await expect(page.getByLabel("Workspace key", { exact: true })).toBeVisible();
  const colors = await page.locator(".entry-key").evaluate(async (field) => {
    await document.fonts.ready;
    const style = getComputedStyle(field);
    return {
      border: style.borderColor,
      inner: style.backgroundColor,
      outer: getComputedStyle(document.body).backgroundColor,
      monoLoaded: Array.from(document.fonts).some(
        (face) => face.family.replaceAll('"', "") === "Geist Mono" && face.status === "loaded",
      ),
    };
  });
  expect(colors.monoLoaded).toBe(true);
  expect(contrast(colors.border, colors.inner)).toBeGreaterThanOrEqual(3);
  expect(contrast(colors.border, colors.outer)).toBeGreaterThanOrEqual(3);
});

for (const language of ["Java", "Python", "JavaScript", "TypeScript"]) {
  test(`${language} controls stay reachable with text spacing on narrow touch screens`, async ({
    page,
  }) => {
    await page.setViewportSize({ width: 320, height: 900 });
    await signInToWorkspace(page);
    await page.addStyleTag({
      content:
        "* { letter-spacing: .12em !important; word-spacing: .16em !important; line-height: 1.5 !important; } p { margin-bottom: 2em !important; }",
    });
    await page.getByRole("combobox", { name: "Language" }).selectOption({ label: language });
    const clipped = await page
      .locator(".workspace > .panel")
      .first()
      .evaluate((panel) => {
        const bounds = panel.getBoundingClientRect();
        return Array.from(
          panel.querySelectorAll(
            ".editor-tools button, .source-actions button, .source-heading select",
          ),
        )
          .filter((control) => {
            const box = control.getBoundingClientRect();
            return box.left < bounds.left || box.right > bounds.right;
          })
          .map((control) => control.textContent?.trim());
      });
    expect(clipped, language).toEqual([]);
    await page.getByRole("button", { name: "Clear", exact: true }).tap();
    await expect(page.getByRole("textbox", { name: `${language} source code` })).toHaveText("");
    await expect(
      page.getByRole("button", { name: `Scan ${language}`, exact: true }),
    ).toBeDisabled();
  });
}

test("selected syntax remains readable through source-to-sink navigation", async ({ page }) => {
  await signInToWorkspace(page);
  await page.getByRole("button", { name: "Scan Java", exact: true }).click();
  await page.getByRole("button", { name: "sink Statement.executeQuery Line 8" }).click();
  expect(await page.evaluate(() => window.getSelection()?.toString())).toBe(
    "statement.executeQuery(query)",
  );
  const selection = await page.locator(".cm-content").evaluate((content) =>
    Array.from(content.querySelectorAll("span"))
      .filter((token) => token.textContent?.trim())
      .map((token) => {
        const style = getComputedStyle(token, "::selection");
        return { color: style.color, background: style.backgroundColor };
      }),
  );
  expect(selection.length).toBeGreaterThan(0);
  for (const colors of selection) {
    expect(contrast(colors.color, colors.background)).toBeGreaterThanOrEqual(4.5);
  }
  await page.getByRole("textbox", { name: "Java source code" }).press("Control+End");
  const bracket = page.locator(".cm-matchingBracket").first();
  await expect(bracket).toBeVisible();
  const bracketColors = await bracket.evaluate((token) => {
    const style = getComputedStyle(token);
    return { color: style.color, background: style.backgroundColor };
  });
  expect(contrast(bracketColors.color, bracketColors.background)).toBeGreaterThanOrEqual(4.5);
});
