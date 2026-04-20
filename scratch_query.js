"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const postgres_storage_service_1 = require("./src/infrastructure/storageService/postgres-storage.service");
const core_1 = require("@credo-ts/core");
const node_1 = require("@credo-ts/node");
async function run() {
    const dependencyManager = new core_1.DependencyManager();
    dependencyManager.registerInstance(core_1.InjectionSymbols.StorageService, new postgres_storage_service_1.PostgresStorageService());
    const agent = new core_1.Agent({
        config: {
            label: "test",
            walletConfig: { id: "test", key: "test" },
            logger: new core_1.ConsoleLogger(core_1.LogLevel.debug)
        },
        dependencies: node_1.agentDependencies,
    }, dependencyManager);
    try {
        await agent.initialize();
        await agent.dids.getCreatedDids({ did: "did:web:localhost:3000" });
    }
    catch (e) {
        console.error(e);
    }
    finally {
        await agent.shutdown();
        process.exit(0);
    }
}
run();
//# sourceMappingURL=scratch_query.js.map