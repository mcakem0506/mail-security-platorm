/**
 * Проверка, что консоль действительно монтируется, а не только собирается.
 *
 * CI до этого проверял типы, сборку и наличие строк в бандле. Ни одна из этих проверок не
 * падает, если приложение бросает исключение при первом рендере, — а именно это и ломает
 * мажорное обновление зависимости вроде react-router 6 → 7: типы совпадают, сборка проходит,
 * строки на месте, экран пустой.
 *
 * Сборка здесь отдельная, одним файлом в формате IIFE: jsdom исполняет классический скрипт, но
 * не ES-модули. Запросы к API подменены ответом 401, поэтому ожидаемый результат — экран входа:
 * это первое, что видит неавторизованный пользователь, и путь, проходящий через роутер,
 * контекст и разметку.
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import react from "@vitejs/plugin-react";
import { JSDOM, VirtualConsole } from "jsdom";
import { build } from "vite";

const root = process.cwd();
const outDir = path.join(root, "dist-smoke");

/** Собрать приложение одним классическим скриптом. */
async function buildBundle() {
  await build({
    configFile: false,
    root,
    plugins: [react()],
    logLevel: "warn",
    // React выбирает ветку по process.env.NODE_ENV; в библиотечном режиме vite её не
    // подставляет, и без этого бандл падает на обращении к process.
    define: { "process.env.NODE_ENV": '"production"' },
    build: {
      outDir,
      emptyOutDir: true,
      target: "es2022",
      sourcemap: false,
      cssCodeSplit: false,
      lib: {
        entry: path.join(root, "src", "main.tsx"),
        formats: ["iife"],
        name: "MspConsoleSmoke",
        fileName: () => "console.js",
      },
    },
  });
  const bundle = path.join(outDir, "console.js");
  if (!fs.existsSync(bundle)) throw new Error(`сборка не создала ${bundle}`);
  return fs.readFileSync(bundle, "utf8");
}

/** Ответ, который отдаёт неавторизованному клиенту настоящий API. */
function unauthorized() {
  return {
    ok: false,
    status: 401,
    statusText: "Unauthorized",
    headers: { get: () => null },
    json: async () => ({ detail: "Требуется вход" }),
    text: async () => '{"detail":"Требуется вход"}',
  };
}

async function main() {
  const code = await buildBundle();

  const problems = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (error) => problems.push(`jsdomError: ${error.message}`));
  virtualConsole.on("error", (...args) => problems.push(`console.error: ${args.join(" ")}`));

  const dom = new JSDOM(
    '<!doctype html><html lang="ru"><body><div id="root"></div></body></html>',
    {
      url: "http://localhost/",
      runScripts: "dangerously",
      pretendToBeVisual: true,
      virtualConsole,
    },
  );

  const { window } = dom;
  window.fetch = async () => unauthorized();
  window.matchMedia =
    window.matchMedia ||
    (() => ({ matches: false, addEventListener() {}, removeEventListener() {} }));

  const script = window.document.createElement("script");
  script.textContent = code;
  window.document.body.appendChild(script);

  // Первый рендер синхронный, запрос сессии — нет. Несколько тиков макрозадач дают React
  // довести до конца эффект, который его выполняет.
  for (let i = 0; i < 20; i += 1) {
    await new Promise((resolve) => window.setTimeout(resolve, 10));
  }

  const rootNode = window.document.getElementById("root");
  const text = (rootNode?.textContent || "").trim();

  if (problems.length) {
    console.error("при монтировании консоли были ошибки:");
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }
  if (!rootNode || rootNode.childNodes.length === 0) {
    console.error("корневой элемент пуст: приложение собралось, но не смонтировалось");
    process.exit(1);
  }
  if (!text.includes("Mail Security Console")) {
    console.error(`экран входа не отрисован, в корне: ${text.slice(0, 200)}`);
    process.exit(1);
  }

  console.log(`консоль смонтировалась, отрисован экран входа (${text.length} символов текста)`);
  fs.rmSync(outDir, { recursive: true, force: true });
}

main().catch((error) => {
  console.error(`проверка монтирования не выполнилась: ${error.stack || error}`);
  process.exit(1);
});
