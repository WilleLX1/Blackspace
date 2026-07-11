import { expect, test } from "@playwright/test";

test("localhost opens the private-alpha onboarding with a persistent development mode", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Compatibility Web — HTTP development only")).toBeVisible();
  await expect(page.getByRole("heading", { name: /Your conversations/ })).toBeVisible();
  await expect(page.getByText(/Unaudited private alpha/)).toBeVisible();
  await expect(page.getByLabel("Server invitation")).toBeVisible();
  await expect(page.getByRole("button", { name: /Create my private space/ })).toBeVisible();
});
