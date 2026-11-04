// @ts-check
import {themes as prismThemes} from 'prism-react-renderer';
import { remarkAlert } from 'remark-github-blockquote-alert';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Bugterium',
  tagline: 'Trilingual HTB/OSCP walkthroughs, web security reference and pentest tooling',
  favicon: 'img/favicon.svg',

  future: { v4: true },

  url: 'https://methodman.pages.dev',
  baseUrl: '/',

  organizationName: 'N3xu666',
  projectName: 'Bugterium',

  onBrokenLinks: 'warn',
  onBrokenAnchors: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    format: 'detect',
  },

  plugins: [
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'reference',
        path: 'docs/reference',
        routeBasePath: 'reference',
        sidebarPath: './sidebarsReference.js',
        remarkPlugins: [remarkAlert],
      },
    ],
  ],

  presets: [
    [
      'classic',
      ({
        docs: {
          path: 'docs/writeups',
          sidebarPath: './sidebars.js',
          remarkPlugins: [remarkAlert],
          routeBasePath: 'writeups',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig: {
    image: 'img/docusaurus-social-card.jpg',
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: false,
    },
    navbar: {
      hideOnScroll: false,
      title: 'Bugterium',
      logo: {
        alt: 'Bugterium',
        src: 'img/logo.svg',
      },
      items: [
        { to: '/writeups', label: 'Writeups', position: 'left', exact: false },
        { to: '/reference', label: 'Reference', position: 'left', exact: false },
        { href: 'https://github.com/N3xu666/MethodMan', label: 'GitHub', position: 'right' },
      ],
    },
    footer: {
      style: 'dark',
      links: [],
      copyright: `Bugterium - CC BY-NC 4.0 | Built with Docusaurus`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  },
};

export default config;