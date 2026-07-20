module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  collectCoverageFrom: ['src/crypto/envelopeEncryption.ts'],
  coverageReporters: ['text'],
  moduleNameMapper: {
    '^@zerovault/auth-shared$': '<rootDir>/../../packages/auth-shared/src/index.ts',
  },
};
