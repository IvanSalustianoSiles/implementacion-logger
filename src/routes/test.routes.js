import { CustomRouter } from "./custom.router.js";

class TestRouterManager extends CustomRouter {
    init () {
        this.get("/", async(req, res) => {
            res.sendUserError("OK");
        });
    };
};
// Ejemplo de manejo del CustomRouter (cuando ya lo haya usado, borro este archivo)
const TestRouter = new TestRouterManager().getRouter();

export default TestRouter;