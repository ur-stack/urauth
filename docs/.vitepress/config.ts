import { defineConfig } from "vitepress";
import { configureDiagramsPlugin } from "vitepress-plugin-diagrams";
import { packageSidebars } from "./sidebar-generated";

export default defineConfig({
  markdown: {
    config: (md) => {
      configureDiagramsPlugin(md, {
        diagramsDir: "docs/public/diagrams",
        publicPath: "/diagrams",
        krokiServerUrl: "https://kroki.io",
      });
    },
  },

  title: "urauth",
  description:
    "Unified authentication & authorization — JWT, OAuth2, RBAC, multi-tenant. Python and TypeScript.",

  themeConfig: {
    nav: [
      { text: "Overview", link: "/overview/" },
      {
        text: "Packages",
        items: [
          {
            text: "Backend",
            items: [
              { text: "Python", link: "/packages/py/" },
              { text: "TypeScript", link: "/packages/ts/" },
              { text: "Node.js", link: "/packages/node/" },
            ],
          },
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
              { text: "React", link: "/packages/react/" },
              { text: "Next.js", link: "/packages/next/" },
            ],
          },
        ],
      },
    ],

    sidebar: {
      "/overview/": [
        {
          text: "Overview",
          items: [
            { text: "Overview", link: "/overview/" },
            { text: "Security", link: "/overview/security" },
            { text: "Integrations", link: "/overview/integrations" },
            { text: "About", link: "/overview/about" },
            { text: "Contributing", link: "/overview/contributing" },
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
