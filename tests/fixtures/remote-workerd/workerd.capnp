using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "hello", worker = .helloWorker),
  ],
  sockets = [
    (
      name = "http",
      address = "*:8787",
      http = (),
      service = "hello",
    ),
  ],
);

const helloWorker :Workerd.Worker = (
  compatibilityDate = "2026-08-07",
  modules = [
    (name = "hello.mjs", esModule = embed "hello.mjs"),
  ],
);
