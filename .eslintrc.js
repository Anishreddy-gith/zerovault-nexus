module.exports = {
  root: true,
  env: { es2022: true, node: true, jest: true },
  extends: ["eslint:recommended", "prettier"],
  parser: "@typescript-eslint/parser",
  plugins: ["@typescript-eslint"],
  rules: {
    "no-unused-vars": "off",
    "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
  },
  parserOptions: { ecmaVersion: "latest", sourceType: "module" },
  ignorePatterns: ["coverage", "dist", "node_modules"],
};
