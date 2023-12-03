module.exports = {
	transform: {
		"^.+\\.(t|j)sx?$": "@swc/jest",
	},
	testEnvironment: 'node',
	testPathIgnorePatterns: ['/node_modules/', 'utils'],
};
