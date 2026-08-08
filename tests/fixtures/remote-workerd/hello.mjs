const handler = {
  async fetch() {
    return new Response("Hello, World!\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};

export default handler;

export const validation = {
  async test() {
    const response = await handler.fetch();
    const body = await response.text();
    if (response.status !== 200 || body !== "Hello, World!\n") {
      throw new Error(`unexpected hello response: ${response.status} ${JSON.stringify(body)}`);
    }
  },
};
