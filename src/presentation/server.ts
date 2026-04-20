import express, { type Express, type Router } from "express";
import cors from "cors";

interface Options {
  port: number;
}
export class Server {
  public readonly app: Express;
  private readonly port: number;

  constructor({ port }: Options) {
    this.app = express();
    this.port = port || 3000;
    this.configure();
  }

  private configure() {
    this.app.use(express.static("public"));
    this.app.use(cors());
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
  }

  public get getApp() {
    return this.app;
  }

  setRoutes(router: Router) {
    this.app.use(router);
  }

  public start(): void {
    this.app.listen(this.port, () => {
      console.log(`Server running on port ${this.port}`);

      // Debug: List all registered routes
      /* this.app.router.stack.forEach((middleware: any) => {
        if (middleware.route) {
          console.log(
            `Route: ${Object.keys(middleware.route.methods).join(", ").toUpperCase()} ${middleware.route.path}`,
          );
        } else if (middleware.name === "router") {
          middleware.handle.stack.forEach((handler: any) => {
            if (handler.route) {
              console.log(
                `Route (nested): ${Object.keys(handler.route.methods).join(", ").toUpperCase()} ${handler.route.path}`,
              );
            }
          });
        }
      }); */
    });
  }
}
