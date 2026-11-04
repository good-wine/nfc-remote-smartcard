// Crea nfc-extension.zip pronto per Chrome Web Store / Firefox Add-ons.
// Usa il primo archiviatore disponibile: `zip` o, in fallback, `7z` (il
// comando `zip` non è installato di default su tutte le distro).
import { rmSync } from "node:fs";
import { execSync } from "node:child_process";

const has = (cmd) => {
  try {
    execSync(`command -v ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};

rmSync("nfc-extension.zip", { force: true });
if (has("zip")) {
  execSync("(cd dist && zip -r ../nfc-extension.zip .)", { stdio: "inherit" });
} else if (has("7z")) {
  execSync("(cd dist && 7z a -tzip ../nfc-extension.zip .)", { stdio: "inherit" });
} else {
  console.error("serve `zip` oppure `7z` per creare nfc-extension.zip");
  process.exit(1);
}
console.log("zip ok -> nfc-extension.zip");
