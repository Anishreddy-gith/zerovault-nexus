module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleNameMapper: {
    '^@zerovault/auth-shared$': '<rootDir>/../../packages/auth-shared/src/index.ts',
  },
};
