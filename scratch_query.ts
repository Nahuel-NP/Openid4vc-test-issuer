import { PostgresStorageService } from "./src/infrastructure/storageService/postgres-storage.service";
import { Agent, LogLevel, ConsoleLogger, InitConfig, InjectionSymbols, DependencyManager } from "@credo-ts/core";
import { agentDependencies } from "@credo-ts/node";

async function run() {
  const dependencyManager = new DependencyManager();
  dependencyManager.registerInstance(InjectionSymbols.StorageService, new PostgresStorageService());

  const agent = new Agent({
    config: {
      label: "test",
      walletConfig: { id: "test", key: "test" },
      logger: new ConsoleLogger(LogLevel.debug)
    },
    dependencies: agentDependencies,
  }, dependencyManager);

  try {
    await agent.initialize();
    await agent.dids.getCreatedDids({ did: "did:web:localhost:3000" });
  } catch (e) {
    console.error(e);
  } finally {
    await agent.shutdown();
    process.exit(0);
  }
}

run();
