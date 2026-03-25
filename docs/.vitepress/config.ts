import { defineConfig } from "vitepress";
import { packageSidebars } from "./sidebar-generated";

export default defineConfig({
  title: "urauth",
  description:
    "Unified authentication & authorization — JWT, OAuth2, RBAC, multi-tenant. Python and TypeScript.",

  themeConfig: {
    nav: [
      { text: "Guide", link: "/guide/" },
      {
        text: "Packages",
        items: [
          { text: "Python (urauth)", link: "/packages/py/" },
          { text: "TypeScript (@urauth/ts)", link: "/packages/ts/" },
          { text: "Node.js (@urauth/node)", link: "/packages/node/" },
          {
            text: "Middleware",
            items: [
              { text: "Hono", link: "/packages/hono/" },
              { text: "Express", link: "/packages/express/" },
              { text: "Fastify", link: "/packages/fastify/" },
              { text: "H3 / Nitro", link: "/packages/h3/" },
            ],
          },
          {
            text: "Frontend",
            items: [
              { text: "Vue", link: "/packages/vue/" },
              { text: "Nuxt", link: "/packages/nuxt/" },
            ],
          },
        ],
      },
    ],

    sidebar: {
      "/guide/": [
        {
          text: "Guide",
          items: [
            { text: "Overview", link: "/guide/" },
            { text: "Getting Started", link: "/guide/getting-started" },
            { text: "Core Concepts", link: "/guide/concepts" },
          ],
        },
      ],
      ...packageSidebars,
    },

    socialLinks: [
      { icon: "github", link: "https://github.com/grandmagus/urauth" },
    ],

    search: {
      provider: "local",
    },

    footer: {
      message: "Released under the MIT License.",
    },
  },
});
