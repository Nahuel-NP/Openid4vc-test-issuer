import {
  Agent,
  DependencyManager,
  DidsModule,
  InitConfig,
  JwkDidRegistrar,
  JwkDidResolver,
  KeyDidRegistrar,
  KeyDidResolver,
  WebDidResolver,
  InjectionSymbols,
  SdJwtVcModule,
  Kms,
  LogLevel,
  ConsoleLogger
} from "@credo-ts/core";
import { agentDependencies } from "@credo-ts/node";
import {
  OpenId4VcIssuerModuleConfigOptions,
  OpenId4VcModule,
  OpenId4VcVerifierModuleConfigOptions,
} from "@credo-ts/openid4vc";
import {
  buildKeyManagementModule,
  VaultKeyManagementModule,
} from "../keyManagement/key-management-service.builder";
import { PostgresStorageService } from "../storageService/postgres-storage.service";
import { envs } from "../../config/envs";

type OpenId4VCModuleConfig =
  | {
      role: "issuer" | "verifier";
      openIdConfig: OpenId4VcModule<
        OpenId4VcIssuerModuleConfigOptions | undefined | null,
        OpenId4VcVerifierModuleConfigOptions | undefined | null
      >;
    }
  | {
      role: "holder";
      openIdConfig: OpenId4VcModule;
    };

export class CredoAgentBuilder {
  private config!: InitConfig;
  private openId4VcModule!: OpenId4VcModule;

  setConfiguration(config: InitConfig): this {
    this.config = config;
    return this;
  }

  setOpenId4VpModule(config: OpenId4VCModuleConfig): this {
    switch (config.role) {
      case "issuer":
        this.openId4VcModule = config.openIdConfig;
        break;
      case "holder":
        this.openId4VcModule = config.openIdConfig;
        break;
      case "verifier":
        this.openId4VcModule = config.openIdConfig;
        break;
    }
    return this;
  }

  async build(): Promise<Agent> {
    const dependencyManager = new DependencyManager();
    dependencyManager.registerInstance(
      InjectionSymbols.StorageService,
      new PostgresStorageService(),
    );

    const vaultKms = new VaultKeyManagementModule(
      envs.VAULT_ADDR,
      envs.VAULT_TRANSIT_PATH,
    );

    await vaultKms.initialize();

    const agent = new Agent(
      {
        config: {
          ...this.config,
          logger: new ConsoleLogger(LogLevel.debug),
        },
        dependencies: agentDependencies,
        modules: {
          openid4vc: this.openId4VcModule,
          dids: new DidsModule({
            resolvers: [
              new WebDidResolver(),
              new KeyDidResolver(),
              new JwkDidResolver(),
            ],
            registrars: [new KeyDidRegistrar(), new JwkDidRegistrar()],
          }),
          keyManagement: new Kms.KeyManagementModule({
            backends: [vaultKms],
          }),
          sdJwtVc: new SdJwtVcModule(),
        },
      },
      dependencyManager,
    );

    await agent.initialize();
    await vaultKms.rebuildKeyMappings(agent.context);

    return agent;
  }
}
