const { spawnSync } = require('node:child_process');

const jestArguments = process.argv.slice(2).filter((argument) => argument !== '--');
const result = spawnSync(process.execPath, [require.resolve('jest/bin/jest'), ...jestArguments], {
  stdio: 'inherit',
});

process.exitCode = result.status ?? 1;
